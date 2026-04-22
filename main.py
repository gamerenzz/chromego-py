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
from collections import OrderedDict
from urllib.parse import urlparse, parse_qs

# ==================== 全局设置 ====================
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

def format_server(addr: str) -> str:
    """处理 IPv6 地址，确保其带有中括号"""
    addr = addr.strip('[]')
    if ":" in addr and "." not in addr: # 简单的 IPv6 判断
        return f"[{addr}]"
    return addr

def parse_bw_int(val) -> int:
    if not val: return 100
    m = re.search(r'(\d+)', str(val))
    return int(m.group(1)) if m else 100

def make_fingerprint(p: dict) -> str:
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|{p.get('uuid') or p.get('password') or p.get('auth-str','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

# ====================== 核心解析逻辑 ======================
def process_clash(data: str):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for p in proxies:
            if not isinstance(p, dict) or not p.get('server'): continue
            
            # 使用 OrderedDict 强制字段顺序：name 第一
            new_p = OrderedDict()
            auth = p.get('auth-str') or p.get('auth_str') or p.get('password') or ''
            loc = get_location(p.get('server'))
            
            new_p['name'] = f"{loc}-{p.get('type','').upper()}-{len(extracted_proxies)+1}"
            new_p['server'] = format_server(p.get('server'))
            new_p['port'] = int(p.get('port'))
            new_p['type'] = p.get('type')
            
            if new_p['type'] == 'hysteria':
                new_p['auth_str'] = auth
                new_p['auth-str'] = auth
                new_p['up'] = parse_bw_int(p.get('up'))
                new_p['down'] = parse_bw_int(p.get('down'))
                new_p['fast-open'] = False
                new_p['skip-cert-verify'] = True
                new_p['alpn'] = ['h3']
            elif new_p['type'] == 'hysteria2':
                new_p['password'] = auth
                new_p['auth'] = auth
                new_p['sni'] = p.get('sni') or 'www.bing.com'
                new_p['skip-cert-verify'] = True
                new_p['alpn'] = ['h3']
            else:
                # 其他类型（VLESS等）保持原样但确保 name 在前
                for k, v in p.items():
                    if k not in new_p: new_p[k] = v

            fp = make_fingerprint(new_p)
            if fp not in servers_list:
                extracted_proxies.append(new_p)
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
                auth = content.get('auth_str') or content.get('auth') or content.get('password', '')
                
                new_p = OrderedDict()
                new_p['name'] = f"{get_location(host)}-{typ.upper()}-{len(extracted_proxies)+1}"
                new_p['server'] = format_server(host)
                new_p['port'] = int(port)
                new_p['type'] = typ
                
                if typ == "hysteria":
                    new_p['auth_str'] = auth
                    new_p['auth-str'] = auth
                    new_p['up'] = parse_bw_int(content.get('up'))
                    new_p['down'] = parse_bw_int(content.get('down'))
                    new_p['fast-open'] = False
                    new_p['skip-cert-verify'] = True
                    new_p['alpn'] = ['h3']
                else:
                    new_p['password'] = auth
                    new_p['auth'] = auth
                    new_p['sni'] = content.get('sni') or 'www.bing.com'
                    new_p['skip-cert-verify'] = True
                    new_p['alpn'] = ['h3']

                fp = make_fingerprint(new_p)
                if fp not in servers_list:
                    extracted_proxies.append(new_p)
                    servers_list.append(fp)
        
        # VLESS 逻辑保持有序
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): continue
            if (ob.get('protocol') or ob.get('type') or '').lower() == 'vless':
                vnext = ob.get('settings', {}).get('vnext', [{}])[0]
                server = vnext.get('address')
                if not server: continue
                stream = ob.get('streamSettings', {})
                reality = stream.get('realitySettings', {}) or stream.get('tlsSettings', {})
                network = stream.get('network', 'tcp')
                
                new_p = OrderedDict()
                new_p['name'] = f"{get_location(server)}-VLESS-{len(extracted_proxies)+1}"
                new_p['server'] = format_server(server)
                new_p['port'] = int(vnext.get('port', 443))
                new_p['type'] = "vless"
                new_p['uuid'] = vnext.get('users', [{}])[0].get('id')
                if network == 'tcp': new_p['flow'] = vnext.get('users', [{}])[0].get('flow', '')
                new_p['network'] = network
                new_p['tls'] = True
                new_p['sni'] = reality.get('serverName', '')
                new_p['client-fingerprint'] = reality.get('fingerprint', 'chrome')
                new_p['alpn'] = ['h3']
                
                if stream.get('security') == 'reality':
                    new_p['reality-opts'] = {"public-key": reality.get('publicKey', ''), "short-id": reality.get('shortId', '')}
                    new_p['skip-cert-verify'] = False
                else:
                    new_p['skip-cert-verify'] = True

                if network == 'xhttp':
                    new_p['xhttp-opts'] = {"path": stream.get('xhttpSettings', {}).get('path', '/'), "mode": "auto"}

                fp = make_fingerprint(new_p)
                if fp not in servers_list:
                    extracted_proxies.append(new_p)
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
    # 特别注意：必须设置 sort_keys=False 才能保持 OrderedDict 的顺序
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)
    print(f"✅ 任务完成，提取节点: {len(extracted_proxies)}")
