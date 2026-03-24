# -*- coding: UTF-8 -*-
"""
Final Fixed Version - 2026-03-24
- 修复 base64.txt（VLESS + Hysteria2 完整可用）
- 增强 Hysteria/Hysteria2 IPv4 提取
- 输出更友好
"""

import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import base64
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

def get_location(ip: str) -> str:
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(ip.strip('[]'))
        country = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{country}-{city}" if city else country
    except:
        return "UNK"

def make_fingerprint(proxy: dict) -> str:
    key_parts = [
        str(proxy.get('server', '')).strip('[]'),
        str(proxy.get('port', '')),
        str(proxy.get('type', '')),
        str(proxy.get('uuid', proxy.get('password', ''))),
        str(proxy.get('network', 'tcp')),
        str(proxy.get('tls', False)),
        str(proxy.get('servername', proxy.get('sni', ''))),
        str(proxy.get('flow', '')),
    ]
    return hashlib.md5("|".join(key_parts).lower().encode()).hexdigest()

def normalize_name(proxy: dict, index: int, sub_index: int) -> str:
    loc = get_location(proxy.get('server', ''))
    typ = proxy.get('type', 'unk').upper()
    return f"{loc}-{typ}-{index+1}-{sub_index+1}"

def parse_server_port(server_str: str):
    """支持 IPv4 / IPv6 格式"""
    server_str = server_str.strip()
    if server_str.startswith('['):  # IPv6 [2001:...]:port
        match = re.match(r'\[([^\]]+)\]:(\d+)', server_str)
        if match:
            return match.group(1), int(match.group(2))
    elif ':' in server_str and not server_str.count(':') > 1:  # IPv4
        parts = server_str.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1])
    return server_str, 443

def process_urls(urls_file: str, processor):
    try:
        with open(urls_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        for idx, url in enumerate(urls):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')
                processor(data, idx)
                logging.info(f"✓ 处理成功 [{idx+1}/{len(urls)}]: {url}")
            except Exception as e:
                logging.error(f"✗ 处理失败 {url}: {e}")
    except Exception as e:
        logging.error(f"读取文件 {urls_file} 失败: {e}")

# ==================== 协议处理器 ====================

def process_clash_meta(data, index):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for i, p in enumerate(proxies):
            if not isinstance(p, dict) or 'server' not in p: continue
            p = dict(p)
            fp = make_fingerprint(p)
            if fp in servers_list: continue
            p['name'] = normalize_name(p, index, i)
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logging.error(f"Clash Meta 处理失败 {index}: {e}")

def process_hysteria(data, index):
    try:
        content = json.loads(data)
        servers = content.get('server') or content.get('servers', [])
        if isinstance(servers, str): servers = [servers]
        for i, srv in enumerate(servers if isinstance(servers, list) else [servers]):
            if not srv: continue
            server, port = parse_server_port(srv)
            # 优先尝试提取 IPv4（如果有）
            if ':' in server and server.count(':') > 1:  # 是 IPv6，尝试找 IPv4
                server = content.get('bindIPv4') or server
            auth = content.get('auth_str') or content.get('auth', content.get('password', ''))
            sni = content.get('server_name', content.get('sni', ''))
            p = {
                "name": normalize_name({"server": server, "type": "hysteria"}, index, i),
                "type": "hysteria", "server": server, "port": port,
                "auth-str": auth, "up": 80, "down": 100,
                "sni": sni, "skip-cert-verify": content.get('insecure', True),
                "fast-open": True
            }
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logging.error(f"Hysteria 处理失败 {index}: {e}")

def process_hysteria2(data, index):
    try:
        content = json.loads(data)
        server_str = content.get('server', '')
        if not server_str: return
        server, port = parse_server_port(server_str)
        # 优先 IPv4
        if ':' in server and server.count(':') > 1:
            server = content.get('bindIPv4') or server
        auth = content.get('auth') or content.get('password', '')
        tls = content.get('tls', {}) or {}
        sni = tls.get('sni', '')
        p = {
            "name": normalize_name({"server": server, "type": "hysteria2"}, index, 0),
            "type": "hysteria2", "server": server, "port": port,
            "password": auth, "sni": sni,
            "skip-cert-verify": tls.get('insecure', True)
        }
        fp = make_fingerprint(p)
        if fp not in servers_list:
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logging.error(f"Hysteria2 处理失败 {index}: {e}")

def process_xray_singbox(data, index):
    try:
        content = json.loads(data)
        outbounds = content.get('outbounds', []) or content.get('proxies', [])
        for i, ob in enumerate(outbounds):
            if not isinstance(ob, dict): continue
            proto = ob.get('protocol', ob.get('type', '')).lower()
            settings = ob.get('settings', {}) or ob
            stream = ob.get('streamSettings', {}) or ob.get('transport', {})

            server = settings.get('address') or settings.get('server')
            port = settings.get('port')
            if not server: continue
            if port is None:
                server, port = parse_server_port(server)
            else:
                port = int(port)

            p = {"server": server, "port": port}

            if proto in ('vless', 'vmess'):
                uuid = settings.get('users', [{}])[0].get('id') or settings.get('uuid')
                if not uuid: continue
                p.update({
                    "type": proto, "uuid": uuid,
                    "network": stream.get('network', 'tcp'),
                    "tls": stream.get('security', 'none') != 'none',
                    "servername": stream.get('tlsSettings', {}).get('serverName') or 
                                  stream.get('realitySettings', {}).get('serverName', ''),
                    "flow": settings.get('users', [{}])[0].get('flow', ''),
                    "skip-cert-verify": True
                })
                if p.get('network') == 'ws':
                    p["ws-opts"] = {"path": stream.get('wsSettings', {}).get('path', '/')}
            elif proto == 'trojan':
                p.update({"type": "trojan", "password": settings.get('password') or '', "skip-cert-verify": True})
            elif proto in ('shadowsocks', 'ss'):
                p.update({
                    "type": "ss",
                    "password": settings.get('password'),
                    "cipher": settings.get('method', 'aes-256-gcm')
                })
            else:
                continue

            p['name'] = normalize_name(p, index, i)
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logging.error(f"Xray/Sing-box 处理失败 {index}: {e}")

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    # 处理所有 urls
    process_urls("urls/clash_meta_urls.txt", process_clash_meta)
    process_urls("urls/hysteria_urls.txt", process_hysteria)
    process_urls("urls/hysteria2_urls.txt", process_hysteria2)
    process_urls("urls/xray_urls.txt", process_xray_singbox)
    process_urls("urls/singbox_urls.txt", process_xray_singbox)
    process_urls("urls/ss_urls.txt", process_xray_singbox)

    logging.info(f"总共提取到 {len(extracted_proxies)} 个有效节点")

    # 输出 Clash Meta YAML
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)

    # ==================== 修复后的 base64 输出 ====================
    all_links = []
    for p in extracted_proxies:
        typ = p.get('type', '').lower()
        name = p.get('name', 'node')

        if typ == 'vless':
            link = (f"vless://{p.get('uuid')}@{p['server']}:{p['port']}?"
                    f"type={p.get('network','tcp')}&security={'tls' if p.get('tls') else 'none'}"
                    f"&sni={p.get('servername','')}&flow={p.get('flow','')}"
                    f"&fp=chrome&alpn=h3,http/1.1&allowInsecure=1"
                    f"#{name}")
            all_links.append(link)

        elif typ == 'hysteria2':
            link = f"hysteria2://{p.get('password')}@{p['server']}:{p['port']}?insecure=1&sni={p.get('sni','')}#{name}"
            all_links.append(link)

        elif typ == 'hysteria':
            link = f"hy://{p.get('auth-str', p.get('password', ''))}@{p['server']}:{p['port']}?insecure=1&sni={p.get('sni','')}#{name}"
            all_links.append(link)

        elif typ == 'ss':
            ss_userinfo = f"{p.get('cipher', 'aes-256-gcm')}:{p.get('password')}"
            ss_link = f"ss://{base64.b64encode(ss_userinfo.encode()).decode()}@{p['server']}:{p['port']}#{name}"
            all_links.append(ss_link)

    with open("outputs/base64.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_links))

    # 额外纯 VLESS base64 订阅（单个字符串，方便导入）
    vless_only = [ln for ln in all_links if ln.startswith("vless://")]
    with open("outputs/vless_subscription.txt", "w", encoding="utf-8") as f:
        if vless_only:
            f.write(base64.b64encode("\n".join(vless_only).encode()).decode())

    logging.info("输出完成！")
    logging.info("   → outputs/clash_meta.yaml （推荐用 Clash / Hiddify）")
    logging.info("   → outputs/base64.txt （已修复，可直接导入 v2rayN / Nekobox）")
    logging.info("   → outputs/vless_subscription.txt （纯 VLESS 订阅）")
