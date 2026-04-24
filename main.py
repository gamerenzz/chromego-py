#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.7.1 - 完整恢复版
- 修复：补全 process_json 逻辑，确保 Sing-box/Hysteria 节点不丢失
- 修复：补全 parse_server_port 工具函数
- 支持：SS, VMess, VLESS, Hysteria1/2, Sing-box JSON, Clash YAML
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

geo_reader = None
try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception:
    logger.warning("GeoLite2-City.mmdb 未找到。")

def get_location(host: str) -> str:
    if not geo_reader or not host: return "🏳️UNK"
    ip = host
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) and ":" not in host:
        try: ip = socket.gethostbyname(host)
        except: pass
    try:
        resp = geo_reader.city(ip.strip('[]'))
        c_code = resp.country.iso_code or "UNK"
        flags = {"CN": "🇨🇳", "US": "🇺🇸", "JP": "🇯🇵", "HK": "🇭🇰", "SG": "🇸🇬", "TW": "🇹🇼", "DE": "🇩🇪", "FR": "🇫🇷", "GB": "🇬🇧", "KR": "🇰🇷", "NL": "🇳🇱", "RU": "🇷🇺", "CA": "🇨🇦", "AU": "🇦🇺", "IN": "🇮🇳"}
        return f"{flags.get(c_code, '🏳️')}{c_code}"
    except: return "🏳️UNK"

def make_fingerprint(p: dict) -> str:
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|" \
          f"{p.get('uuid') or p.get('password') or p.get('auth-str','')}|" \
          f"{p.get('network','')}|{p.get('sni','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def ensure_alpn_list(alpn):
    if not alpn: return ["h3"]
    if isinstance(alpn, str): return [alpn]
    if isinstance(alpn, list): return alpn
    return ["h3"]

def safe_base64_decode(data: str) -> str:
    try:
        data = data.replace('-', '+').replace('_', '/')
        padding = '=' * (-len(data) % 4)
        return base64.b64decode(data + padding).decode('utf-8', errors='ignore')
    except: return ""

def preprocess_subscription(data: str) -> str:
    content = data.strip()
    if not content: return content
    if not any(content.startswith(p) for p in ('vmess://', 'vless://', 'ss://', 'hysteria2://', 'hy2://', '{', 'proxies:')):
        decoded = safe_base64_decode(content)
        if decoded: return decoded
    return content

# ====================== 核心解析逻辑 ======================

def parse_ss_link(link: str) -> dict | None:
    try:
        url_part = link.split('#')[0]
        url = urlparse(url_part)
        server = url.hostname
        port = url.port
        userinfo = safe_base64_decode(url.username) if url.username else ""
        if ':' not in userinfo: return None
        method, password = userinfo.split(':', 1)
        loc = get_location(server)
        return {"name": f"{loc}-SS-{len(extracted_proxies)+1}","type": "ss","server": server,"port": int(port),"cipher": method,"password": password}
    except: return None

def parse_vmess_link(link: str) -> dict | None:
    try:
        b64_data = link[8:].split('#')[0]
        config = json.loads(safe_base64_decode(b64_data))
        server = config.get('add')
        loc = get_location(server)
        p = {"name": f"{loc}-VMESS-{len(extracted_proxies)+1}","type": "vmess","server": server,"port": int(config.get('port')),"uuid": config.get('id'),"alterId": int(config.get('aid', 0)),"cipher": config.get('scy', 'auto'),"network": config.get('net', 'tcp'),"tls": config.get('tls') in ('tls', True, 1),"sni": config.get('sni'),"udp": True}
        if p['network'] == 'ws': p['ws-opts'] = {"path": config.get('path', '/'), "headers": {"Host": config.get('host', '')}}
        return {k: v for k, v in p.items() if v not in (None, '', {}, [])}
    except: return None

def parse_vless_link(link: str) -> dict | None:
    try:
        url = urlparse(link)
        params = parse_qs(url.query)
        server = url.hostname
        loc = get_location(server)
        p = {"name": f"{loc}-VLESS-{len(extracted_proxies)+1}","type": "vless","server": server,"port": int(url.port) if url.port else 443,"uuid": url.username,"network": params.get('type', ['tcp'])[0],"tls": params.get('security', ['none'])[0] in ('tls', 'reality'),"sni": params.get('sni', [''])[0] or params.get('serverName', [''])[0],"flow": params.get('flow', [''])[0],"client-fingerprint": params.get('fp', ['chrome'])[0],"alpn": ensure_alpn_list(params.get('alpn', ["h3"]))}
        if params.get('security', [''])[0] == 'reality': p['reality-opts'] = {"public-key": params.get('pbk', [''])[0], "short-id": params.get('sid', [''])[0]}
        if p['network'] == 'xhttp': p['xhttp-opts'] = {"path": params.get('path', ['/'])[0], "mode": params.get('mode', ['auto'])[0]}
        return {k: v for k, v in p.items() if v not in (None, '', {}, [])}
    except: return None

def parse_hysteria2_link(link: str) -> dict | None:
    try:
        url = urlparse(link)
        params = parse_qs(url.query)
        server = url.hostname
        loc = get_location(server)
        p = {"name": f"{loc}-HY2-{len(extracted_proxies)+1}","type": "hysteria2","server": server,"port": int(url.port) if url.port else 443,"password": url.username,"sni": params.get('sni', [''])[0],"skip-cert-verify": params.get('insecure', ['0'])[0] == '1',"alpn": ["h3"]}
        return {k: v for k, v in p.items() if v not in (None, '', {}, [])}
    except: return None

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
        # 兼容 Hysteria 原生格式
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str): servers = [servers]
            typ = "hysteria2" if any(',' in str(s) for s in servers) or "hysteria2" in str(content).lower() else "hysteria"
            for s in servers:
                server, main_port, ports_range = parse_server_port(s)
                tls_cfg = content.get('tls', {})
                loc = get_location(server)
                p = {"name": f"{loc}-{typ.upper()}-{len(extracted_proxies)+1}","type": typ,"server": server,"port": main_port,"password": content.get('auth') or content.get('password') or content.get('auth_str', ''),"sni": content.get('sni') or content.get('peer') or tls_cfg.get('sni', ''),"skip-cert-verify": content.get('insecure', tls_cfg.get('insecure', True)),"alpn": ensure_alpn_list(content.get('alpn'))}
                if typ == "hysteria":
                    p["auth-str"] = p["password"]
                    p["up"] = content.get('up_mbps') or 100
                    p["down"] = content.get('down_mbps') or 100
                if ports_range: p['ports'] = ports_range
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)
        
        # 兼容 Sing-box outbounds 格式
        for ob in content.get('outbounds', []):
            protocol = (ob.get('protocol') or ob.get('type','')).lower()
            if protocol not in ('vless', 'hysteria', 'hysteria2', 'tuic'): continue
            
            server = ob.get('server')
            if not server:
                vnext = ob.get('settings', {}).get('vnext', [{}])[0]
                server = vnext.get('address')
            if not server: continue

            loc = get_location(server)
            p = {"name": f"{loc}-{protocol.upper()}-{len(extracted_proxies)+1}", "type": protocol, "server": server, "port": int(ob.get('server_port') or ob.get('port') or 443)}
            
            # 针对不同协议提取字段
            if protocol == 'vless':
                p['uuid'] = ob.get('uuid') or ob.get('settings', {}).get('vnext', [{}])[0].get('users', [{}])[0].get('id')
                tls = ob.get('tls', {})
                p['tls'] = tls.get('enabled', False)
                p['sni'] = tls.get('server_name')
                if ob.get('transport', {}).get('type') == 'xhttp':
                    xh = ob.get('transport', {})
                    p['network'] = 'xhttp'
                    p['xhttp-opts'] = {"path": xh.get('path'), "mode": xh.get('mode')}

            elif protocol in ('hysteria', 'hysteria2'):
                p['password'] = ob.get('password') or ob.get('auth_str')
                p['sni'] = ob.get('tls', {}).get('server_name')
                p['skip-cert-verify'] = ob.get('tls', {}).get('insecure', True)

            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except: pass

# ====================== 主程序 ======================

def process_file(file_path: str):
    if not os.path.exists(file_path): return
    logger.info(f"读取订阅列表: {file_path}")
    with open(file_path, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')
            
            data = preprocess_subscription(raw)
            if url.endswith(('.yaml', '.yml')) or 'proxies:' in data:
                process_clash(data)
            else:
                lines = [l.strip() for l in data.splitlines() if l.strip()]
                parsed_count = 0
                for l in lines:
                    p = None
                    if l.startswith('vless://'): p = parse_vless_link(l)
                    elif l.startswith('vmess://'): p = parse_vmess_link(l)
                    elif l.startswith('ss://'): p = parse_ss_link(l)
                    elif l.startswith(('hysteria2://', 'hy2://')): p = parse_hysteria2_link(l)
                    
                    if p:
                        fp = make_fingerprint(p)
                        if fp not in servers_list:
                            extracted_proxies.append(p)
                            servers_list.append(fp)
                        parsed_count += 1
                
                # 如果没按行解析出节点，说明可能是 JSON 格式
                if parsed_count == 0:
                    process_json(data)
        except Exception as e:
            logger.error(f"处理错误 {url}: {e}")

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    
    # 自动处理 urls 目录下所有 txt 文件
    if os.path.exists("urls"):
        for filename in sorted(os.listdir("urls")):
            if filename.endswith(".txt"):
                process_file(os.path.join("urls", filename))
    
    node_names = [p['name'] for p in extracted_proxies]
    
    clash_config = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info", "ipv6": True,
        "dns": {"enabled": True, "nameserver": ["119.29.29.29", "223.5.5.5"], "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16"},
        "proxies": extracted_proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "DIRECT"] + node_names},
            {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": node_names},
            {"name": "🎯 全球直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]}
        ],
        "rules": ["GEOIP,CN,🎯 全球直连", "MATCH,🚀 节点选择"]
    }
    
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    
    print(f"✅ 处理完成，去重后共 {len(extracted_proxies)} 个节点。")
