#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v4.4.0 - 修复混合订阅解析与解码版
- 修复：修复 Base64/明文订阅混合识别失败导致 0 节点的问题
- 修复：修复 Hysteria2 等协议中的 URL 编码（%2F等）密码解析
- 新增：增加对 SSR (ShadowsocksR) 协议的解析支持
- 保持：多源去重与 Gemini/AI 专业分流、Reality/xhttp 兼容
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
from urllib.parse import urlparse, parse_qs, unquote # 引入 unquote 解码

# ==================== 全局设置 ====================
socket.setdefaulttimeout(15)
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(message)s')
logger = logging.getLogger("ChromeGo")

EXCLUDE_TYPES = ['juicity', 'mieru', 'shadowquic'] 
servers_list = []
extracted_proxies = []

geo_reader = None
try:
    if os.path.exists('GeoLite2-City.mmdb'):
        geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    logger.warning("GeoLite2-City.mmdb 未找到。")

# ====================== 工具函数 ======================

def get_location(host: str) -> str:
    if not geo_reader or not host: return "🏳️"
    ip = host
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) and ":" not in host:
        try: ip = socket.gethostbyname(host)
        except: pass
    try:
        resp = geo_reader.city(ip.strip('[]'))
        c_code = resp.country.iso_code or "UNK"
        flags = {"CN": "🇨🇳", "US": "🇺🇸", "JP": "🇯🇵", "HK": "🇭🇰", "SG": "🇸🇬", "TW": "🇹🇼", "DE": "🇩🇪", "FR": "🇫🇷", "KR": "🇰🇷", "GB": "🇬🇧"}
        return f"{flags.get(c_code, '🏳️')}{c_code}"
    except: return "🏳️UNK"

def make_fingerprint(p: dict) -> str:
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|" \
          f"{p.get('uuid') or p.get('password') or p.get('auth-str','')}|" \
          f"{p.get('sni','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def safe_base64_decode(data: str) -> str:
    try:
        data = data.replace('-', '+').replace('_', '/')
        padding = '=' * (-len(data) % 4)
        return base64.b64decode(data + padding).decode('utf-8', errors='ignore')
    except: return ""

def parse_server_port(srv):
    srv = str(srv).strip()
    pr = None
    if ',' in srv:
        parts = srv.split(',')
        if len(parts) > 1 and '-' in parts[-1]: pr = parts[-1].strip()
        srv = parts[0].strip()
    if srv.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', srv)
        if m: return m.group(1), int(m.group(2)), pr
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit(): return parts[0], int(parts[1]), pr
    return srv, 443, pr

# ====================== 深度解析逻辑 ======================

def add_proxy(p: dict):
    if not p or not p.get('server'): return
    p_type = str(p.get('type', '')).lower()
    if p_type in EXCLUDE_TYPES: return

    fp = make_fingerprint(p)
    if fp not in servers_list:
        loc = get_location(p.get('server'))
        idx = len(extracted_proxies) + 1
        p['name'] = f"{loc}-{p_type.upper()}-{idx}"
        p['udp'] = True
        extracted_proxies.append(p)
        servers_list.append(fp)

def parse_uri(l: str):
    l = l.strip()
    if not l: return
    try:
        if l.startswith('vless://'):
            u = urlparse(l); q = parse_qs(u.query)
            p_port = u.port if u.port else 443
            p = {"type": "vless", "server": u.hostname, "port": int(p_port), "uuid": u.username,
                 "network": q.get('type', ['tcp'])[0], "tls": True,
                 "sni": q.get('sni', [''])[0] or q.get('serverName', [''])[0], 
                 "flow": q.get('flow', [''])[0]}
            if q.get('security', [''])[0] == 'reality':
                p['reality-opts'] = {"public-key": q.get('pbk', [''])[0], "short-id": q.get('sid', [''])[0]}
            if p['network'] == 'xhttp':
                p['xhttp-opts'] = {"path": q.get('path', ['/'])[0], "mode": q.get('mode', ['auto'])[0]}
            add_proxy(p)
            
        elif l.startswith('vmess://'):
            c = json.loads(safe_base64_decode(l[8:]))
            add_proxy({"type": "vmess", "server": c.get('add'), "port": int(c.get('port')), "uuid": c.get('id'), "network": c.get('net', 'tcp'), "tls": c.get('tls') in ('tls', True, 1)})
            
        elif l.startswith('ss://'):
            u = urlparse(l)
            userinfo = safe_base64_decode(unquote(u.username)) if u.username else ""
            if ':' in userinfo:
                m, pwd = userinfo.split(':', 1)
                add_proxy({"type": "ss", "server": u.hostname, "port": u.port, "cipher": m, "password": pwd})
                
        elif l.startswith(('hysteria2://', 'hy2://')):
            u = urlparse(l); q = parse_qs(u.query)
            # 修复密码被 URL 编码的问题
            pwd = unquote(u.username) if u.username else ""
            add_proxy({"type": "hysteria2", "server": u.hostname, "port": u.port or 443, "password": pwd, "sni": q.get('sni',[''])[0], "skip-cert-verify": True})
            
        # 新增：SSR 支持解析
        elif l.startswith('ssr://'):
            decoded = safe_base64_decode(l[6:])
            if decoded:
                parts = decoded.split('/?')
                m = parts[0].split(':')
                if len(m) >= 6:
                    add_proxy({
                        "type": "ssr", "server": m[0], "port": int(m[1]), 
                        "protocol": m[2], "cipher": m[3], "obfs": m[4], 
                        "password": safe_base64_decode(m[5])
                    })
    except Exception as e:
        pass # 容错，跳过无法解析的单行

def process_native_json(data: str):
    try:
        c = json.loads(data)
        if 'up_mbps' in c: 
            h, p, _ = parse_server_port(c.get('server'))
            add_proxy({
                "type": "hysteria", "server": h, "port": p, 
                "auth-str": c.get('auth_str') or c.get('password'), 
                "up": c.get('up_mbps'), "down": c.get('down_mbps'), 
                "sni": c.get('server_name') or c.get('sni'),
                "skip-cert-verify": True, "alpn": ["h3"]
            })
        elif 'auth' in c and 'bandwidth' in c:
            h, p, pr = parse_server_port(c.get('server'))
            add_proxy({
                "type": "hysteria2", "server": h, "port": p, 
                "password": c.get('auth'), 
                "sni": c.get('tls',{}).get('sni') or c.get('sni'),
                "skip-cert-verify": True, "alpn": ["h3"]
            })
        for ob in c.get('outbounds', []):
            typ = (ob.get('type') or ob.get('protocol') or '').lower()
            h = ob.get('server') or ob.get('settings', {}).get('vnext', [{}])[0].get('address')
            if h:
                p_port = ob.get('server_port') or ob.get('port') or 443
                p = {"type": typ, "server": h, "port": int(p_port)}
                p['uuid'] = ob.get('uuid') or ob.get('settings', {}).get('vnext', [{}])[0].get('users', [{}])[0].get('id')
                p['password'] = ob.get('password') or ob.get('auth_str')
                p['sni'] = ob.get('tls', {}).get('server_name') or ob.get('sni')
                p['skip-cert-verify'] = True
                if typ in ('hysteria', 'hysteria2'): p['alpn'] = ["h3"]
                add_proxy(p)
    except: pass

def process_file(file_path: str):
    if not os.path.exists(file_path): return
    with open(file_path, 'r', encoding='utf-8') as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode('utf-8', errors='ignore').strip()
            
            if raw.startswith('{'): process_native_json(raw)
            elif 'proxies:' in raw:
                import yaml
                c = yaml.safe_load(raw)
                for p in (c.get('proxies', []) or []): add_proxy(p)
            else:
                # 修复：正确判定是明文集合还是 Base64 集合
                if '://' in raw:
                    content = raw  # 如果内容包含 :// 显然是明文合集
                else:
                    content = safe_base64_decode(raw) # 否则当作 Base64 解码
                
                for line in content.splitlines(): 
                    parse_uri(line)
        except Exception as e:
            logger.error(f"处理 {url} 时出错: {e}")

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    if os.path.exists("urls"):
        for f in sorted(os.listdir("urls")):
            if f.endswith(".txt"): process_file(os.path.join("urls", f))

    node_names = [p['name'] for p in extracted_proxies]

    if not extracted_proxies:
        print("⚠️ 未提取到任何节点，请检查网络或订阅链接！")
        exit()

    clash_config = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "ipv6": True,
        "dns": {
            "enabled": True, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["223.5.5.5", "119.29.29.29"],
            "fallback": ["https://dns.google/dns-query", "https://1.1.1.1/dns-query"],
            "nameserver-policy": {
                "geosite:google,gemini,openai,anthropic,netflix,disney,tiktok": "https://dns.google/dns-query",
                "geosite:cn": "223.5.5.5"
            }
        },
        "proxies": extracted_proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "⚖️ 负载均衡", "DIRECT"] + node_names},
            {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": node_names},
            {"name": "⚖️ 负载均衡", "type": "load-balance", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": node_names},
            {"name": "🤖 Gemini/AI", "type": "select", "proxies": ["🚀 节点选择", "♻️ 自动选择"]},
            {"name": "🎯 全球直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]}
        ],
        "rules": [
            "DOMAIN-SUFFIX,gemini.google.com,🤖 Gemini/AI",
            "DOMAIN-SUFFIX,openai.com,🤖 Gemini/AI",
            "DOMAIN-SUFFIX,anthropic.com,🤖 Gemini/AI",
            "DOMAIN-SUFFIX,claude.ai,🤖 Gemini/AI",
            "DOMAIN-SUFFIX,netflix.com,🚀 节点选择",
            "DOMAIN-KEYWORD,google,🤖 Gemini/AI",
            "DOMAIN-KEYWORD,openai,🤖 Gemini/AI",
            "DOMAIN-KEYWORD,tiktok,🚀 节点选择",
            "GEOIP,CN,🎯 全球直连",
            "MATCH,🚀 节点选择"
        ]
    }

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"✅ 处理完成！已修复协议解析支持。总提取节点数: {len(extracted_proxies)}")
