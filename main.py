# -*- coding: UTF-8 -*-
"""
最终完善版 - 正确处理 Hysteria1 和 Hysteria2 所有参数（含 peer、up/down、alpn 等）
Y系列 → sources.txt (前缀 Y-)
Z系列 → sources-j.txt (前缀 Z-)
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

def process_file(file_path, prefix):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=25) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')

                if url.endswith(('.yaml', '.yml')):
                    process_clash(data, prefix)
                else:
                    process_json(data, prefix)

                logging.info(f"✓ {prefix}系列 处理完成: {url}")
            except Exception as e:
                logging.error(f"✗ {prefix}系列 处理失败 {url}: {e}")
    except Exception as e:
        logging.error(f"读取 {file_path} 失败: {e}")

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
        
        # ====================== Hysteria / Hysteria2 核心处理 ======================
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str): servers = [servers]
            
            # 判断是 hysteria1 还是 hysteria2
            typ = "hysteria2" if "hysteria2" in str(content).lower() or "hy2" in str(content).lower() else "hysteria"
            
            for i, s in enumerate(servers):
                if not s: continue
                server, main_port = parse_server_port(s)
                
                p = {
                    "name": f"{prefix}{get_location(server)}-{typ.upper()}-{i+1}",
                    "type": typ,
                    "server": server,
                    "port": main_port,
                    "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                    "sni": content.get('sni') or content.get('peer') or content.get('server_name') or "",
                    "skip-cert-verify": content.get('insecure', True),
                    "alpn": content.get('alpn', 'h3')
                }
                
                # Hysteria1 特有参数
                if typ == "hysteria":
                    p["up"] = content.get('upmbps') or content.get('up') or 50
                    p["down"] = content.get('downmbps') or content.get('down') or 100
                
                # Hysteria2 跳跃端口
                ports_range = content.get('server_ports') or content.get('hop_ports')
                if ports_range:
                    p['ports'] = ports_range
                elif isinstance(s, str) and ',' in s:
                    parts = [part.strip() for part in s.split(',')]
                    if len(parts) > 1 and '-' in parts[-1]:
                        p['ports'] = parts[-1]
                
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)

        # outbounds 处理（保留）
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): continue
            proto = (ob.get('protocol') or ob.get('type') or '').lower()
            if proto not in ('vless', 'vmess', 'trojan', 'ss', 'hysteria', 'hysteria2'): continue
            settings = ob.get('settings', ob)
            server = settings.get('address') or settings.get('server')
            if not server: continue
            port = int(settings.get('port', 443))
            p = {"server": server, "port": port, "type": proto}
            if proto == 'vless':
                p['uuid'] = settings.get('users', [{}])[0].get('id')
            p['name'] = f"{prefix}{get_location(server)}-{proto.upper()}-{len(extracted_proxies)+1}"
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logging.error(f"JSON 处理异常: {e}")

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    logging.info("=== 开始提取节点 ===")
    process_file("urls/sources.txt", "Y-")
    process_file("urls/sources-j.txt", "Z-")

    logging.info(f"总共提取到 {len(extracted_proxies)} 个有效节点")

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)

    logging.info("✅ clash_meta.yaml 已成功生成！")
