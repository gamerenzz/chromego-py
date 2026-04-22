#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import hashlib
import re
import base64
import socket
from urllib.parse import urlparse, parse_qs

socket.setdefaulttimeout(15)
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)8s | %(message)s')
logger = logging.getLogger("ChromeGo")

servers_list: list[str] = []
extracted_proxies: list[dict] = []

geo_reader = None
try: geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except: logger.warning("GeoLite2-City.mmdb 未找到")

def get_flag(code: str) -> str:
    if not code or len(code) != 2 or code == "UNK": return ""
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)

def get_location(ip: str) -> str:
    if not geo_reader or not ip: return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        flag = f"{get_flag(c)} " if get_flag(c) else ""
        return f"{flag}{c}-{resp.city.name or ''}".strip('-')
    except: return "UNK"

def parse_bw_int(val) -> int:
    if not val: return 100
    m = re.search(r'(\d+)', str(val))
    return int(m.group(1)) if m else 100

def make_fingerprint(p: dict) -> str:
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|{p.get('uuid') or p.get('password') or p.get('auth-str','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def process_clash(data: str):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for p in proxies:
            if not isinstance(p, dict) or not p.get('server'): continue
            p = dict(p)
            
            # 【像素级对齐】Hysteria 1 核心字段清理
            if p.get('type') == 'hysteria':
                auth = p.get('auth-str') or p.get('auth_str') or p.get('password') or ''
                # 只保留网友版本有的字段，删除冗余的 sni 和 protocol
                clean_p = {
                    "name": "", # 稍后填入
                    "server": p.get('server'),
                    "port": int(p.get('port')),
                    "type": "hysteria",
                    "auth_str": auth,
                    "auth-str": auth,
                    "up": parse_bw_int(p.get('up')),
                    "down": parse_bw_int(p.get('down')),
                    "fast-open": False,
                    "skip-cert-verify": True,
                    "alpn": ["h3"]
                }
                p = clean_p
            elif p.get('type') == 'hysteria2':
                auth = p.get('password') or p.get('auth') or ''
                p = {
                    "name": "",
                    "server": p.get('server'),
                    "port": int(p.get('port')),
                    "type": "hysteria2",
                    "password": auth,
                    "auth": auth,
                    "sni": p.get('sni', 'www.bing.com'),
                    "skip-cert-verify": True,
                    "alpn": ["h3"]
                }
            
            fp = make_fingerprint(p)
            if fp not in servers_list:
                loc = get_location(p.get('server'))
                p['name'] = f"{loc}-{p.get('type','').upper()}-{len(extracted_proxies)+1}"
                extracted_proxies.append(p)
                servers_list.append(fp)
    except: pass

def process_json(data: str):
    try:
        content = json.loads(data)
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str): servers = [servers]
            is_h2 = "hysteria2" in str(content).lower() or 'auth' in content or 'password' in content
            typ = "hysteria2" if is_h2 else "hysteria"
            
            for s in servers:
                if not s: continue
                addr = str(s).split(',')[0]
                host, port = (addr.rsplit(':', 1) if ':' in addr else (addr, 443))
                host = host.strip('[]')
                auth = content.get('auth_str') or content.get('auth') or content.get('password', '')
                
                if typ == "hysteria":
                    # 【像素级对齐】H1 不输出 SNI 和 Protocol
                    p = {
                        "server": host, "port": int(port), "type": "hysteria",
                        "auth_str": auth, "auth-str": auth,
                        "up": parse_bw_int(content.get('up')), "down": parse_bw_int(content.get('down')),
                        "fast-open": False, "skip-cert-verify": True, "alpn": ["h3"]
                    }
                else:
                    p = {
                        "server": host, "port": int(port), "type": "hysteria2",
                        "password": auth, "auth": auth,
                        "sni": content.get('sni') or content.get('server_name') or 'www.bing.com',
                        "skip-cert-verify": True, "alpn": ["h3"]
                    }
                
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    p['name'] = f"{get_location(host)}-{typ.upper()}-{len(extracted_proxies)+1}"
                    extracted_proxies.append(p)
                    servers_list.append(fp)
        
        # VLESS 全量逻辑
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): continue
            if (ob.get('protocol') or ob.get('type') or '').lower() == 'vless':
                vnext = ob.get('settings', {}).get('vnext', [{}])[0]
                server = vnext.get('address')
                if not server: continue
                stream = ob.get('streamSettings', {})
                reality = stream.get('realitySettings', {}) or stream.get('tlsSettings', {})
                network = stream.get('network', 'tcp')
                p = {
                    "type": "vless", "server": server, "port": int(vnext.get('port', 443)),
                    "uuid": vnext.get('users', [{}])[0].get('id'), "network": network, "tls": True,
                    "sni": reality.get('serverName', ''), "client-fingerprint": reality.get('fingerprint', 'chrome'), "alpn": ["h3"]
                }
                if network == 'tcp': p['flow'] = vnext.get('users', [{}])[0].get('flow', '')
                if stream.get('security') == 'reality':
                    p['reality-opts'] = {"public-key": reality.get('publicKey', ''), "short-id": reality.get('shortId', '')}
                    p['skip-cert-verify'] = False
                else: p['skip-cert-verify'] = True
                if network == 'xhttp': p['xhttp-opts'] = {"path": stream.get('xhttpSettings', {}).get('path', '/'), "mode": "auto"}
                p = {k: v for k, v in p.items() if v not in (None, '', {}, [])}
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    p['name'] = f"{get_location(server)}-VLESS-{len(extracted_proxies)+1}"
                    extracted_proxies.append(p)
                    servers_list.append(fp)
    except: pass

def process_file(file_path: str):
    with open(file_path, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
            process_clash(raw) if ('proxies:' in raw or 'proxy:' in raw) else process_json(raw)
        except: pass

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    process_file("urls/sources.txt")
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)
    print(f"✅ 任务完成，提取节点: {len(extracted_proxies)}")
