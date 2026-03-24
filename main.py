# -*- coding: UTF-8 -*-
"""
最优最终版 main.py
- 只输出 clash_meta.yaml
- sources.txt 统一管理所有源
- Y- = 最初 Alvin9999 源
- J- = backup/img 补充源
"""

import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import hashlib
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

servers_list = []
extracted_proxies = []
geo_reader = None

try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    logging.warning("GeoLite2-City.mmdb not found")

def get_location(ip):
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{c}-{city}" if city else c
    except:
        return "UNK"

def make_fingerprint(p):
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|{p.get('uuid') or p.get('password') or p.get('auth-str','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def parse_server_port(srv):
    srv = str(srv).strip()
    if srv.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', srv)
        if m:
            return m.group(1), int(m.group(2))
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1])
    return srv, 443

def process_urls():
    try:
        with open("urls/sources.txt", 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # 判断 Y 系列还是 J 系列
            is_y = any(x in line for x in ["Alvin9999/pac2", "free9999/ipupdate", "githubip.xyz", "gitlabip.xyz/Alvin9999/pac2"])
            prefix = "Y-" if is_y else "J-"

            try:
                req = urllib.request.Request(line, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=25) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')

                if line.endswith(('.yaml', '.yml')):
                    process_clash(data, prefix)
                else:
                    process_json(data, prefix)

                logging.info(f"✓ 处理完成 [{line_num+1}]: {line}")
            except Exception as e:
                logging.error(f"✗ 处理失败 [{line_num+1}]: {line} → {e}")
    except Exception as e:
        logging.error(f"读取 sources.txt 失败: {e}")

def process_clash(data, prefix):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for i, p in enumerate(proxies):
            if not isinstance(p, dict) or not p.get('server'):
                continue
            p = dict(p)
            fp = make_fingerprint(p)
            if fp in servers_list: continue
            p['name'] = f"{prefix}{get_location(p.get('server'))}-{p.get('type','unk').upper()}-{i+1}"
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logging.error(f"Clash 处理异常: {e}")

def process_json(data, prefix):
    try:
        content = json.loads(data)
        # hysteria / hysteria2 / xray / singbox 等通用处理
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str): servers = [servers]
            typ = "hysteria2" if "hysteria2" in str(content).lower() else "hysteria"
            for i, s in enumerate(servers):
                if not s: continue
                server, port = parse_server_port(s)
                p = {
                    "name": f"{prefix}{get_location(server)}-{typ.upper()}-{i+1}",
                    "type": typ,
                    "server": server,
                    "port": port,
                    "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                    "sni": content.get('sni') or (content.get('tls') or {}).get('sni', ''),
                    "skip-cert-verify": True
                }
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)

        # outbounds 处理（xray / singbox 等）
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): continue
            proto = (ob.get('protocol') or ob.get('type') or '').lower()
            if proto not in ('vless', 'vmess', 'trojan', 'ss', 'shadowsocks'): continue
            settings = ob.get('settings', ob)
            server = settings.get('address') or settings.get('server')
            if not server: continue
            port = int(settings.get('port', 443))
            p = {"server": server, "port": port, "type": proto}
            if proto == 'vless':
                p['uuid'] = settings.get('users', [{}])[0].get('id')
            elif proto in ('ss', 'shadowsocks'):
                p['password'] = settings.get('password')
                p['cipher'] = settings.get('method', 'aes-256-gcm')
            p['name'] = f"{prefix}{get_location(server)}-{proto.upper()}-{len(extracted_proxies)+1}"
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logging.error(f"JSON 处理异常: {e}")

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    logging.info("=== 开始处理所有节点源（Y系列 + J系列） ===")
    process_urls()

    logging.info(f"总共提取到 {len(extracted_proxies)} 个有效节点")

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)

    logging.info("✅ clash_meta.yaml 已成功生成并更新！")
    logging.info("输出路径：outputs/clash_meta.yaml")
