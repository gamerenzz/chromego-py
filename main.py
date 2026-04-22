#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.6.3 - 终极稳定版
- 修复：Gemini 解锁增强（优化 DNS 解析与分流规则）
- 修复：Loop detected 策略组死循环报错
- 修复：'alpn' is not a slice 报错
- 修复：DNS 自动解析与国旗命名
"""
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

# ==================== 全局设置 ====================
socket.setdefaulttimeout(15)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("ChromeGo")

servers_list: list[str] = []
extracted_proxies: list[dict] = []

# 地理位置查询
geo_reader = None
try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception:
    logger.warning("GeoLite2-City.mmdb 未找到。")

def get_location(host: str) -> str:
    """解析主机并返回带国旗的地区标识"""
    if not geo_reader or not host:
        return "🏳️UNK"
    
    ip = host
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) and ":" not in host:
        try:
            ip = socket.gethostbyname(host)
        except:
            pass

    try:
        resp = geo_reader.city(ip.strip('[]'))
        c_code = resp.country.iso_code or "UNK"
        flags = {
            "CN": "🇨🇳", "US": "🇺🇸", "JP": "🇯🇵", "HK": "🇭🇰", "SG": "🇸🇬", 
            "TW": "🇹🇼", "DE": "🇩🇪", "FR": "🇫🇷", "GB": "🇬🇧", "KR": "🇰🇷",
            "NL": "🇳🇱", "RU": "🇷🇺", "CA": "🇨🇦", "AU": "🇦🇺", "IN": "🇮🇳"
        }
        return f"{flags.get(c_code, '🏳️')}{c_code}"
    except:
        return "🏳️UNK"

def make_fingerprint(p: dict) -> str:
    """生成节点指纹用于去重"""
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|" \
          f"{p.get('uuid') or p.get('password') or p.get('auth-str','')}|" \
          f"{p.get('network','')}|{p.get('sni','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def ensure_alpn_list(alpn):
    """强制将 ALPN 转换为列表格式，修复 Clash 报错"""
    if not alpn: return ["h3"]
    if isinstance(alpn, str): return [alpn]
    if isinstance(alpn, list): return alpn
    return ["h3"]

def preprocess_subscription(data: str) -> str:
    content = data.strip()
    if not content: return content
    try:
        padding = '=' * (-len(content) % 4)
        decoded = base64.b64decode(content + padding, validate=False).decode('utf-8', errors='ignore')
        if any(decoded.startswith(prefix) for prefix in ('vmess://', 'vless://', 'ss://')):
            return decoded
    except: pass
    return content

# ====================== 核心解析逻辑 ======================

def parse_vless_link(link: str) -> dict | None:
    try:
        if not link.startswith('vless://'): return None
        url = urlparse(link)
        params = parse_qs(url.query)
        server = url.hostname
        loc = get_location(server)
        p = {
            "name": f"{loc}-VLESS-{len(extracted_proxies)+1}",
            "type": "vless",
            "server": server,
            "port": int(url.port) if url.port else 443,
            "uuid": url.username,
            "network": params.get('type', ['tcp'])[0],
            "tls": params.get('security', ['none'])[0] in ('tls', 'reality'),
            "sni": params.get('sni', [''])[0] or params.get('serverName', [''])[0],
            "flow": params.get('flow', [''])[0],
            "client-fingerprint": params.get('fp', ['chrome'])[0],
            "alpn": ensure_alpn_list(params.get('alpn', ["h3"]))
        }
        if params.get('security', [''])[0] == 'reality':
            p['reality-opts'] = {"public-key": params.get('pbk', [''])[0], "short-id": params.get('sid', [''])[0]}
        return {k: v for k, v in p.items() if v not in (None, '', {}, [])}
    except: return None

def process_clash(data: str):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for p in proxies:
            if not isinstance(p, dict) or not p.get('server'): continue
            p = dict(p)
            if 'alpn' in p: p['alpn'] = ensure_alpn_list(p['alpn'])
            fp = make_fingerprint(p)
            if fp in servers_list: continue
            loc = get_location(p.get('server'))
            p['name'] = f"{loc}-{str(p.get('type','')).upper()}-{len(extracted_proxies)+1}"
            extracted_proxies.append(p)
            servers_list.append(fp)
    except: pass

def process_json(data: str):
    try:
        content = json.loads(data)
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str): servers = [servers]
            typ = "hysteria2" if any(',' in str(s) for s in servers) or "hysteria2" in str(content).lower() else "hysteria"
            for s in servers:
                server, main_port, ports_range = parse_server_port(s)
                tls_cfg = content.get('tls', {})
                loc = get_location(server)
                p = {
                    "name": f"{loc}-{typ.upper()}-{len(extracted_proxies)+1}",
                    "type": typ,
                    "server": server,
                    "port": main_port,
                    "password": content.get('auth') or content.get('password') or content.get('auth_str', ''),
                    "sni": content.get('sni') or content.get('peer') or tls_cfg.get('sni', ''),
                    "skip-cert-verify": content.get('insecure', tls_cfg.get('insecure', True)),
                    "alpn": ensure_alpn_list(content.get('alpn'))
                }
                if typ == "hysteria":
                    p["auth-str"] = p["password"]
                    p["up"] = content.get('up_mbps') or 100
                    p["down"] = content.get('down_mbps') or 100
                if ports_range: p['ports'] = ports_range
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)
        for ob in content.get('outbounds', []):
            if (ob.get('protocol') or ob.get('type','')).lower() != 'vless': continue
            vnext = ob.get('settings', {}).get('vnext', [{}])[0]
            server = vnext.get('address')
            if not server: continue
            stream = ob.get('streamSettings', {})
            reality = stream.get('realitySettings', {}) or stream.get('tlsSettings', {})
            loc = get_location(server)
            p = {
                "name": f"{loc}-VLESS-{len(extracted_proxies)+1}",
                "type": "vless",
                "server": server,
                "port": int(vnext.get('port', 443)),
                "uuid": vnext.get('users', [{}])[0].get('id'),
                "network": stream.get('network', 'tcp'),
                "tls": stream.get('security') in ('tls', 'reality'),
                "sni": reality.get('serverName') or stream.get('serverName', ''),
                "alpn": ensure_alpn_list(reality.get('alpn') or stream.get('alpn'))
            }
            if stream.get('security') == 'reality':
                p['reality-opts'] = {"public-key": reality.get('publicKey'), "short-id": reality.get('shortId')}
            if stream.get('network') == 'xhttp':
                xh = stream.get('xhttpSettings', {})
                p['xhttp-opts'] = {"path": xh.get('path', '/'), "mode": xh.get('mode', 'auto')}
            p = {k: v for k, v in p.items() if v not in (None, '', {}, [])}
            if make_fingerprint(p) not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(make_fingerprint(p))
    except: pass

def parse_server_port(srv):
    srv = str(srv).strip()
    ports_range = None
    if ',' in srv:
        parts = srv.split(',')
        if len(parts) > 1 and '-' in parts[-1]: ports_range = parts[-1].strip()
        srv = parts[0].strip()
    if srv.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', srv)
        if m: return m.group(1), int(m.group(2)), ports_range
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit(): return parts[0], int(parts[1]), ports_range
    return srv, 443, ports_range

# ====================== 主程序 ======================

def process_file(file_path: str):
    if not os.path.exists(file_path): return
    with open(file_path, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
            data = preprocess_subscription(raw)
            if url.endswith(('.yaml', '.yml')) or 'proxies:' in data: process_clash(data)
            else:
                lines = [l.strip() for l in data.splitlines() if l.strip()]
                if any(l.startswith('vless://') for l in lines):
                    for l in lines:
                        p = parse_vless_link(l)
                        if p and make_fingerprint(p) not in servers_list:
                            extracted_proxies.append(p)
                            servers_list.append(make_fingerprint(p))
                else: process_json(data)
        except: pass

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    process_file("urls/sources.txt")
    node_names = [p['name'] for p in extracted_proxies]
    
    clash_config = {
        "mixed-port": 7890, 
        "allow-lan": True, 
        "mode": "rule", 
        "log-level": "info", 
        "ipv6": True,
        "dns": {
            "enabled": True, 
            "nameserver": ["8.8.8.8", "1.1.1.1"], # 强化：国外标准 DNS
            "fallback": ["https://dns.google/dns-query", "https://1.1.1.1/dns-query"], # 强化：DoH
            "enhanced-mode": "fake-ip", 
            "fake-ip-range": "198.18.0.1/16"
        },
        "proxies": extracted_proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择", 
                "type": "select", 
                "proxies": ["♻️ 自动选择", "DIRECT"] + node_names 
            },
            {
                "name": "♻️ 自动选择", 
                "type": "url-test", 
                "url": "http://www.gstatic.com/generate_204", 
                "interval": 300, 
                "proxies": node_names
            },
            {
                "name": "🎯 全球直连", 
                "type": "select", 
                "proxies": ["DIRECT", "🚀 节点选择"] 
            }
        ],
        "rules": [
            # 强化：针对 AI/Google 服务的显式规则
            "DOMAIN-KEYWORD,google,🚀 节点选择",
            "DOMAIN-KEYWORD,gemini,🚀 节点选择",
            "DOMAIN-SUFFIX,googleapis.com,🚀 节点选择",
            "DOMAIN-SUFFIX,gstatic.com,🚀 节点选择",
            "GEOIP,CN,🎯 全球直连", 
            "MATCH,🚀 节点选择"
        ]
    }
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"✅ 处理完成，共 {len(extracted_proxies)} 个节点。")
