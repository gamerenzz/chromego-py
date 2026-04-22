#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.6 - 最终完美版
- 修复：DNS 自动解析，彻底解决域名节点显示 UNK 问题
- 修复：VLESS xhttp/Reality/WS 关键字段提取
- 修复：Hysteria 1/2 带宽与 SNI 提取
- 新增：自动生成完整 Clash 策略组（测速、分流、自动选择）
- 新增：国旗 Emoji 命名系统
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
    logger.warning("GeoLite2-City.mmdb 未找到，地理信息将降级。")

def get_location(host: str) -> str:
    """解析主机并返回带国旗的地区标识"""
    if not geo_reader or not host:
        return "🏳️UNK"
    
    # 尝试将域名解析为 IP
    ip = host
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) and ":" not in host:
        try:
            ip = socket.gethostbyname(host)
        except:
            pass # 解析失败则用原 host 尝试查询

    try:
        resp = geo_reader.city(ip.strip('[]'))
        c_code = resp.country.iso_code or "UNK"
        
        # 国旗映射表
        flags = {
            "CN": "🇨🇳", "US": "🇺🇸", "JP": "🇯🇵", "HK": "🇭🇰", "SG": "🇸🇬", 
            "TW": "🇹🇼", "DE": "🇩🇪", "FR": "🇫🇷", "GB": "🇬🇧", "KR": "🇰🇷",
            "NL": "🇳🇱", "RU": "🇷🇺", "CA": "🇨🇦", "AU": "🇦🇺", "IN": "🇮🇳"
        }
        flag = flags.get(c_code, "🏳️")
        return f"{flag}{c_code}"
    except:
        return "🏳️UNK"

def make_fingerprint(p: dict) -> str:
    """生成节点指纹用于严格去重"""
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|" \
          f"{p.get('uuid') or p.get('password') or p.get('auth-str','')}|" \
          f"{p.get('network','')}|{p.get('sni','')}|{p.get('path','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def preprocess_subscription(data: str) -> str:
    content = data.strip()
    if not content: return content
    try:
        padding = '=' * (-len(content) % 4)
        decoded = base64.b64decode(content + padding, validate=False).decode('utf-8', errors='ignore')
        if any(decoded.startswith(prefix) for prefix in ('vmess://', 'vless://', 'ss://', 'hy2://')):
            return decoded
    except: pass
    return content

# ====================== 核心解析逻辑 ======================

def parse_vless_link(link: str) -> dict | None:
    """解析 vless:// 链接"""
    try:
        if not link.startswith('vless://'): return None
        url = urlparse(link)
        uuid = url.username
        server = url.hostname
        port = int(url.port) if url.port else 443
        params = parse_qs(url.query)

        p = {
            "name": f"TMP-{len(extracted_proxies)+1}",
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "network": params.get('type', ['tcp'])[0],
            "tls": params.get('security', ['none'])[0] in ('tls', 'reality'),
            "sni": params.get('sni', [''])[0] or params.get('serverName', [''])[0],
            "flow": params.get('flow', [''])[0],
            "client-fingerprint": params.get('fp', ['chrome'])[0],
        }
        if params.get('security', [''])[0] == 'reality':
            p['reality-opts'] = {"public-key": params.get('pbk', [''])[0], "short-id": params.get('sid', [''])[0]}
        
        # 补全节点名
        loc = get_location(server)
        p['name'] = f"{loc}-VLESS-{len(extracted_proxies)+1}"
        return {k: v for k, v in p.items() if v not in (None, '', {}, [])}
    except: return None

def process_clash(data: str):
    """处理 Clash YAML 源"""
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for p in proxies:
            if not isinstance(p, dict) or not p.get('server'): continue
            p = dict(p)
            fp = make_fingerprint(p)
            if fp in servers_list: continue
           
            loc = get_location(p.get('server'))
            node_type = str(p.get('type', 'UNK')).upper()
            p['name'] = f"{loc}-{node_type}-{len(extracted_proxies)+1}"
           
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e: logger.error(f"Clash 处理异常: {e}")

def process_json(data: str):
    """处理 JSON 源（包含 Hysteria, TUIC, VLESS Outbounds）"""
    try:
        content = json.loads(data)
        
        # 1. 处理 Hysteria / TUIC 根配置
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str): servers = [servers]
            
            has_hop = any(',' in str(s) and '-' in str(s) for s in servers)
            typ = "hysteria2" if has_hop or "hysteria2" in str(content).lower() else "hysteria"
            
            for s in servers:
                if not s: continue
                server, main_port, ports_range = parse_server_port(s)
                tls_cfg = content.get('tls', {})
                sni_val = content.get('sni') or content.get('peer') or content.get('server_name') or tls_cfg.get('sni', '')
                
                loc = get_location(server)
                p = {
                    "name": f"{loc}-{typ.upper()}-{len(extracted_proxies)+1}",
                    "type": typ,
                    "server": server,
                    "port": main_port,
                    "password": content.get('auth') or content.get('password') or content.get('auth_str', ''),
                    "sni": sni_val,
                    "skip-cert-verify": content.get('insecure', tls_cfg.get('insecure', True)),
                    "alpn": content.get('alpn', ["h3"]),
                }
                if typ == "hysteria":
                    p["auth-str"] = p["password"]
                    p["up"] = content.get('up_mbps') or content.get('up') or 100
                    p["down"] = content.get('down_mbps') or content.get('down') or 100
                if ports_range: p['ports'] = ports_range

                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)

        # 2. 处理 V2Ray/Xray Outbounds 格式
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict) or (ob.get('protocol') or ob.get('type','')).lower() != 'vless': continue
            
            settings = ob.get('settings', {})
            vnext = settings.get('vnext', [{}])[0]
            server = vnext.get('address')
            if not server: continue
            
            user = vnext.get('users', [{}])[0]
            stream = ob.get('streamSettings', {})
            reality = stream.get('realitySettings', {}) or stream.get('tlsSettings', {})
            
            loc = get_location(server)
            p = {
                "name": f"{loc}-VLESS-{len(extracted_proxies)+1}",
                "type": "vless",
                "server": server,
                "port": int(vnext.get('port', 443)),
                "uuid": user.get('id'),
                "flow": user.get('flow', ''),
                "network": stream.get('network', 'tcp'),
                "tls": stream.get('security') in ('tls', 'reality', 'xtls'),
                "sni": reality.get('serverName') or stream.get('serverName') or '',
                "client-fingerprint": reality.get('fingerprint', 'chrome'),
                "alpn": reality.get('alpn', ["h3"]),
            }
            if stream.get('security') == 'reality':
                p['reality-opts'] = {"public-key": reality.get('publicKey', ''), "short-id": reality.get('shortId', '')}
            
            # 传输层配置
            net = stream.get('network')
            if net == 'ws':
                ws = stream.get('wsSettings', {})
                p['ws-opts'] = {"path": ws.get('path', '/'), "headers": ws.get('headers', {})}
            elif net == 'xhttp':
                xh = stream.get('xhttpSettings', {})
                p['xhttp-opts'] = {"path": xh.get('path', '/'), "mode": xh.get('mode', 'auto')}
            elif net == 'grpc':
                gp = stream.get('grpcSettings', {})
                p['grpc-opts'] = {"grpc-service-name": gp.get('serviceName', '')}

            p = {k: v for k, v in p.items() if v not in (None, '', {}, [])}
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
                
    except Exception as e: logger.error(f"JSON 处理异常: {e}")

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
            if url.endswith(('.yaml', '.yml')) or 'proxies:' in data:
                process_clash(data)
            else:
                # 检查是否为直链列表
                lines = [l.strip() for l in data.splitlines() if l.strip()]
                if any(l.startswith('vless://') for l in lines):
                    for l in lines:
                        if l.startswith('vless://'):
                            p = parse_vless_link(l)
                            if p and make_fingerprint(p) not in servers_list:
                                extracted_proxies.append(p)
                                servers_list.append(make_fingerprint(p))
                else:
                    process_json(data)
            logger.info(f"✓ 成功处理: {url}")
        except Exception as e: logger.error(f"✗ 失败 {url}: {e}")

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    logger.info("=== ChromeGo Enhanced v3.6 启动 ===")
    
    process_file("urls/sources.txt")
    
    # 构造完整 Clash 配置
    node_names = [p['name'] for p in extracted_proxies]
    clash_config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "dns": {
            "enabled": True,
            "nameserver": ["119.29.29.29", "223.5.5.5", "1.1.1.1"],
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16"
        },
        "proxies": extracted_proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "🎯 全球直连"] + node_names
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
            "DOMAIN-SUFFIX,google.com,🚀 节点选择",
            "DOMAIN-KEYWORD,github,🚀 节点选择",
            "GEOIP,CN,🎯 全球直连",
            "MATCH,🚀 节点选择"
        ]
    }

    output_path = "outputs/clash_meta.yaml"
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    
    logger.info(f"✅ 处理完成！共 {len(extracted_proxies)} 个节点。")
    logger.info(f"📄 完整配置文件已生成: {output_path}")
