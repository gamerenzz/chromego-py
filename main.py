#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.9.0 - 全协议深度提取版
- 修复：支持从 Hysteria1/2, Juicity, Naive, Sing-box, Xray 的原生 JSON 中提取节点
- 修复：生成专业级 DNS 和 Gemini 专用分流规则
- 支持：SS, VMess, VLESS, Hy1/2, Tuic, Juicity
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
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(message)s')
logger = logging.getLogger("ChromeGo")

servers_list = []
extracted_proxies = []

# GeoIP 初始化
geo_reader = None
try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    logger.warning("GeoLite2-City.mmdb 未找到。")

def get_location(host: str) -> str:
    if not geo_reader or not host: return "🏳️"
    ip = host
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) and ":" not in host:
        try: ip = socket.gethostbyname(host)
        except: pass
    try:
        resp = geo_reader.city(ip.strip('[]'))
        c = resp.country.iso_code
        flags = {"CN": "🇨🇳", "US": "🇺🇸", "JP": "🇯🇵", "HK": "🇭🇰", "SG": "🇸🇬", "TW": "🇹🇼", "DE": "🇩🇪", "FR": "🇫🇷", "KR": "🇰🇷"}
        return flags.get(c, "🏳️") + (c if c else "UNK")
    except: return "🏳️UNK"

def make_fingerprint(p: dict) -> str:
    key = f"{p.get('server')}|{p.get('port')}|{p.get('type')}|{p.get('uuid') or p.get('password') or p.get('auth-str')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

# ====================== 深度解析逻辑 ======================

def process_json_content(data: str):
    """
    核心：从你提供的各种原生 config.json 中提取节点
    """
    try:
        c = json.loads(data)
        loc = ""
        p = None

        # 1. 识别 Hysteria 1 (原生格式)
        if 'up_mbps' in c and 'auth_str' in c:
            host, port, _ = parse_server_port(c.get('server'))
            p = {
                "type": "hysteria",
                "server": host, "port": port,
                "auth-str": c.get('auth_str'),
                "up": c.get('up_mbps'), "down": c.get('down_mbps'),
                "sni": c.get('server_name'), "skip-cert-verify": c.get('insecure', True),
                "alpn": ["h3"]
            }

        # 2. 识别 Hysteria 2 (原生格式)
        elif 'auth' in c and 'bandwidth' in c:
            host, port, pr = parse_server_port(c.get('server'))
            p = {
                "type": "hysteria2",
                "server": host, "port": port,
                "password": c.get('auth'),
                "sni": c.get('tls', {}).get('sni'),
                "skip-cert-verify": c.get('tls', {}).get('insecure', True)
            }
            if pr: p['ports'] = pr

        # 3. 识别 Juicity (原生格式)
        elif 'server' in c and 'uuid' in c and 'congestion_control' in c:
            host, port, _ = parse_server_port(c.get('server'))
            p = {
                "type": "juicity",
                "server": host, "port": port,
                "uuid": c.get('uuid'), "password": c.get('password'),
                "sni": c.get('sni'), "skip-cert-verify": c.get('allow_insecure', True)
            }

        # 4. 识别 NaiveProxy (原生格式)
        elif 'proxy' in c and str(c.get('proxy')).startswith('https://'):
            # 格式: https://user:pass@host:port
            raw_url = c.get('proxy').replace('https://', 'http://') # 方便 urlparse
            u = urlparse(raw_url)
            p = {
                "type": "http", # Naive 在 Clash Meta 中通常作为 http 代理
                "server": u.hostname, "port": u.port or 443,
                "username": u.username, "password": u.password,
                "tls": True, "sni": u.hostname
            }

        # 5. 识别 Sing-box / Xray / V2Ray (Outbounds 模式)
        if not p and 'outbounds' in c:
            for ob in c['outbounds']:
                if ob.get('type') in ('vless', 'vmess', 'tuic', 'hysteria2'):
                    host = ob.get('server')
                    if not host: continue
                    p = {
                        "type": ob.get('type'),
                        "server": host, "port": ob.get('server_port') or ob.get('port'),
                        "uuid": ob.get('uuid'), "password": ob.get('password'),
                        "sni": ob.get('tls', {}).get('server_name'),
                        "skip-cert-verify": ob.get('tls', {}).get('insecure', True)
                    }
                    add_to_proxies(p)
            return

        if p: add_to_proxies(p)
    except: pass

def add_to_proxies(p):
    if not p or not p.get('server'): return
    fp = make_fingerprint(p)
    if fp not in servers_list:
        loc = get_location(p['server'])
        p['name'] = f"{loc}-{p['type'].upper()}-{len(extracted_proxies)+1}"
        extracted_proxies.append(p)
        servers_list.append(fp)

def parse_server_port(srv):
    srv = str(srv).strip()
    pr = None
    if ',' in srv:
        parts = srv.split(',')
        if len(parts) > 1 and '-' in parts[-1]: pr = parts[-1]
        srv = parts[0]
    if srv.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', srv)
        if m: return m.group(1), int(m.group(2)), pr
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        return parts[0], int(parts[1]), pr
    return srv, 443, pr

# (此处保留你原有的 parse_vless_link, parse_vmess_link, parse_ss_link 和 process_clash 代码...)
# 为了节省篇幅，假设你已经将这些 URI 解析函数放在了此处。

# ====================== 核心循环 ======================

def process_file(file_path: str):
    if not os.path.exists(file_path): return
    with open(file_path, 'r', encoding='utf-8') as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
            
            # 自动识别格式并处理
            if 'proxies:' in raw or url.endswith(('.yaml', '.yml')):
                # 调用你原有的 process_clash
                import yaml
                content = yaml.safe_load(raw)
                for p in (content.get('proxies', []) or []): add_to_proxies(p)
            elif raw.strip().startswith('{'):
                process_json_content(raw)
            else:
                # 处理 URI 列表
                for line in raw.splitlines():
                    line = line.strip()
                    if not line: continue
                    # 此时调用 parse_vless_link, parse_vmess_link 等
                    # 这里简化示意
                    pass 
        except: pass

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    # 处理所有 txt 文件
    for f in os.listdir("urls"):
        if f.endswith(".txt"): process_file(os.path.join("urls", f))

    node_names = [p['name'] for p in extracted_proxies]

    # ======== 核心：生成能访问 Gemini 的专业配置 ========
    clash_config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "ipv6": True,
        "dns": {
            "enabled": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["223.5.5.5", "119.29.29.29"],
            "fallback": ["https://dns.google/dns-query", "https://1.1.1.1/dns-query"],
            "fallback-filter": {"geoip": True, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"]}
        },
        "proxies": extracted_proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "DIRECT"] + node_names},
            {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": node_names},
            {"name": "🤖 Gemini/AI", "type": "select", "proxies": ["🚀 节点选择", "♻️ 自动选择"]},
            {"name": "🎯 全球直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]}
        ],
        "rules": [
            "DOMAIN-SUFFIX,gemini.google.com,🤖 Gemini/AI",
            "DOMAIN-KEYWORD,google,🤖 Gemini/AI",
            "DOMAIN-SUFFIX,googleapis.com,🤖 Gemini/AI",
            "DOMAIN-SUFFIX,gstatic.com,🤖 Gemini/AI",
            "GEOIP,CN,🎯 全球直连",
            "MATCH,🚀 节点选择"
        ]
    }

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"✅ 完成！提取节点：{len(extracted_proxies)}")
