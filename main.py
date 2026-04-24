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

# ==================== 全局设置 ====================
socket.setdefaulttimeout(15)
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(message)s')
logger = logging.getLogger("ChromeGo")

EXCLUDE_TYPES = ['juicity', 'mieru', 'shadowquic'] 
servers_list = []
extracted_proxies = []

# GeoIP 初始化
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
        flags = {"CN": "🇨🇳", "US": "🇺🇸", "JP": "🇯🇵", "HK": "🇭🇰", "SG": "🇸🇬", "TW": "🇹🇼", "DE": "🇩🇪", "FR": "🇫🇷", "KR": "🇰🇷"}
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

    # 强制清理空字段，但保留嵌套字典
    p = {k: v for k, v in p.items() if v is not None}

    fp = make_fingerprint(p)
    if fp not in servers_list:
        loc = get_location(str(p.get('server')))
        idx = len(extracted_proxies) + 1
        p['name'] = f"{loc}-{p_type.upper()}-{idx}"
        p['udp'] = True
        extracted_proxies.append(p)
        servers_list.append(fp)

def parse_uri(link: str):
    link = link.strip()
    if not link: return
    try:
        if link.startswith('vless://'):
            # 强化版 URI 解析：uuid@host:port
            main_part = link.split('#')[0]
            data_part = main_part[8:]
            uuid_part, rest = data_part.split('@', 1)
            
            # 分离 host:port 和 query
            host_port_part = rest.split('?')[0]
            query_part = rest.split('?')[1] if '?' in rest else ""
            
            host, port, _ = parse_server_port(host_port_part)
            q = parse_qs(query_part)
            
            p = {
                "type": "vless", "server": host, "port": int(port), "uuid": uuid_part,
                "network": q.get('type', ['tcp'])[0], "tls": True, "skip-cert-verify": True,
                "sni": q.get('sni', [None])[0] or q.get('serverName', [None])[0],
                "flow": q.get('flow', [None])[0]
            }
            if q.get('security', [''])[0] == 'reality':
                p['reality-opts'] = {"public-key": q.get('pbk', [''])[0], "short-id": q.get('sid', [''])[0]}
            if p['network'] == 'xhttp':
                p['xhttp-opts'] = {"path": q.get('path', ['/'])[0], "mode": q.get('mode', ['auto'])[0]}
            add_proxy(p)
            
        elif link.startswith('vmess://'):
            c = json.loads(safe_base64_decode(link[8:]))
            add_proxy({"type": "vmess", "server": c.get('add'), "port": int(c.get('port')), "uuid": c.get('id'), "network": c.get('net', 'tcp'), "tls": c.get('tls') in ('tls', True, 1)})
        elif link.startswith('ss://'):
            u = urlparse(link)
            userinfo = safe_base64_decode(u.username) if u.username else ""
            if ':' in userinfo:
                m, pwd = userinfo.split(':', 1)
                add_proxy({"type": "ss", "server": u.hostname, "port": u.port, "cipher": m, "password": pwd})
        elif link.startswith(('hysteria2://', 'hy2://')):
            u = urlparse(link); q = parse_qs(u.query)
            add_proxy({"type": "hysteria2", "server": u.hostname, "port": u.port or 443, "password": u.username, "sni": q.get('sni',[''])[0], "skip-cert-verify": True, "alpn": ["h3"]})
    except: pass

def process_native_json(data: str):
    """
    针对 Xray/Sing-box JSON 进行深度结构化提取
    """
    try:
        c = json.loads(data)
        # 针对 Hysteria 1/2 原生 JSON
        if 'up_mbps' in c:
            h, p, _ = parse_server_port(c.get('server'))
            add_proxy({"type": "hysteria", "server": h, "port": p, "auth-str": c.get('auth_str') or c.get('password'), "up": c.get('up_mbps'), "down": c.get('down_mbps'), "sni": c.get('server_name'), "skip-cert-verify": True, "alpn": ["h3"]})
            return
        
        # 针对 Sing-box/Xray Outbounds
        for ob in c.get('outbounds', []):
            typ = (ob.get('type') or ob.get('protocol') or '').lower()
            if typ not in ('vless', 'vmess', 'tuic', 'hysteria', 'hysteria2'): continue
            
            settings = ob.get('settings', {})
            stream = ob.get('streamSettings', {})
            
            # 关键：从 vnext 提取真正服务器地址和端口
            vnext = settings.get('vnext', [{}])[0]
            server = ob.get('server') or vnext.get('address')
            port = ob.get('port') or ob.get('server_port') or vnext.get('port')
            
            if not server or not port: continue
            
            p = {"type": typ, "server": server, "port": int(port), "skip-cert-verify": True}
            
            # 提取认证信息
            p['uuid'] = ob.get('uuid') or vnext.get('users', [{}])[0].get('id')
            p['password'] = ob.get('password') or ob.get('auth_str')
            
            # 提取 TLS/SNI
            tls_cfg = ob.get('tls', {}) or stream.get('tlsSettings', {})
            p['sni'] = tls_cfg.get('server_name') or tls_cfg.get('serverName') or stream.get('serverName')
            
            # 提取传输层 (xhttp/ws)
            transport = ob.get('transport', {}) or stream
            if (transport.get('network') or transport.get('type')) == 'xhttp':
                p['network'] = 'xhttp'
                xh = transport.get('xhttpSettings') or transport
                p['xhttp-opts'] = {"path": xh.get('path', '/'), "mode": xh.get('mode', 'auto')}
                
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
                content = safe_base64_decode(raw) if not any(raw.startswith(x) for x in ('v','s','h')) else raw
                for line in content.splitlines(): parse_uri(line)
        except: pass

# ====================== 自定义 YAML 导出 ======================
class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data): return True

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    if os.path.exists("urls"):
        for f in sorted(os.listdir("urls")):
            if f.endswith(".txt"): process_file(os.path.join("urls", f))

    node_names = [p['name'] for p in extracted_proxies]
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
            {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "⚖️ 负载均衡", "DIRECT"] + list(node_names)},
            {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": list(node_names)},
            {"name": "⚖️ 负载均衡", "type": "load-balance", "url": "http://www.gstatic.com/generate_204", "interval": 300, "strategy": "consistent-hashing", "proxies": list(node_names)},
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
        yaml.dump(clash_config, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False, default_flow_style=False)
    print(f"✅ 完美合并！VLESS 端口与 Reality 参数已通过深度解析修复。节点数: {len(extracted_proxies)}")
