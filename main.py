#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.5.2 - 纯 Y 系列版（终极修复版）
- 修复 Hysteria up/down 包含字符串 (Mbps) 导致内核解析报错、节点不通的问题
- 增加 Hysteria 1/2 认证字段双重别名兼容 (auth_str/auth-str, password/auth)
- 增加节点名称自动附加国家 Emoji 图标
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
urllib.request.socket.setdefaulttimeout(15)

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
    logger.warning("GeoLite2-City.mmdb 未找到，位置信息将显示 UNK")

def get_flag(code: str) -> str:
    """根据两位国家代码生成对应的 Emoji 国旗"""
    if not code or len(code) != 2 or code == "UNK":
        return ""
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)

def get_location(ip: str) -> str:
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        flag = f"{get_flag(c)} " if get_flag(c) else ""
        city = resp.city.name or ""
        return f"{flag}{c}-{city}" if city else f"{flag}{c}"
    except:
        return "UNK"

def parse_bw(val) -> int:
    """提取带宽值为纯整数，防止 '11 Mbps' 字符串导致内核罢工"""
    if not val:
        return 100
    m = re.search(r'(\d+)', str(val))
    return int(m.group(1)) if m else 100

def make_fingerprint(p: dict) -> str:
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|" \
          f"{p.get('uuid') or p.get('password') or p.get('auth-str','')}|" \
          f"{p.get('network','')}|{p.get('sni','')}|{p.get('servername','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def preprocess_subscription(data: str) -> str:
    content = data.strip()
    if not content:
        return content
    try:
        padding = '=' * (-len(content) % 4)
        decoded = base64.b64decode(content + padding, validate=False).decode('utf-8', errors='ignore')
        if any(decoded.startswith(prefix) for prefix in ('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
            return decoded
    except:
        pass
    return content

# ====================== vless:// 直链解析 ======================
def parse_vless_link(link: str) -> dict | None:
    try:
        if not link.startswith('vless://'): return None
        url = urlparse(link)
        uuid = url.username
        server = url.hostname
        port = int(url.port) if url.port else 443
        params = parse_qs(url.query)

        p = {
            "name": f"{get_location(server)}-VLESS-{len(extracted_proxies)+1}",
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
            p['reality-opts'] = {
                "public-key": params.get('pbk', [''])[0],
                "short-id": params.get('sid', [''])[0]
            }
        return {k: v for k, v in p.items() if v not in (None, '', {}, [])}
    except:
        return None

# ====================== 主处理流程 ======================
def process_file(file_path: str):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
       
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw_data = resp.read().decode('utf-8', errors='ignore')
                
                processed_data = preprocess_subscription(raw_data)

                if url.endswith(('.yaml', '.yml')) or 'proxies:' in processed_data or 'proxy:' in processed_data:
                    process_clash(processed_data)
                else:
                    process_json(processed_data)
                
                logger.info(f"✓ 订阅源处理完成: {url}")
            except Exception as e:
                logger.error(f"✗ 处理失败 {url}: {type(e).__name__}")
    except Exception as e:
        logger.error(f"读取 {file_path} 失败: {e}")

def process_clash(data: str):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for p in proxies:
            if not isinstance(p, dict) or not p.get('server'):
                continue
            p = dict(p)
            
            # 【修复1】严格转换带宽为整数，防 "11 Mbps" 罢工
            if 'up' in p: p['up'] = parse_bw(p['up'])
            if 'down' in p: p['down'] = parse_bw(p['down'])

            # 【修复2】双重别名保底，适应所有 Meta 版本
            if p.get('type') == 'hysteria':
                auth = p.get('auth-str') or p.get('auth_str') or p.get('password') or ''
                p['auth-str'] = auth
                p['auth_str'] = auth
                if 'password' in p: del p['password']
                p['fast-open'] = p.get('fast-open', False)
            elif p.get('type') == 'hysteria2':
                auth = p.get('password') or p.get('auth') or ''
                p['password'] = auth
                p['auth'] = auth

            fp = make_fingerprint(p)
            if fp in servers_list:
                continue
           
            original_name = p.get('name', '')
            if original_name.startswith('Y-'):
                base_name = original_name[2:]
            else:
                loc = get_location(p.get('server'))
                node_type = p.get('type', 'unk').upper()
                base_name = f"{loc}-{node_type}"
            
            p['name'] = f"{base_name}-{len(extracted_proxies)+1}"
            
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logger.error(f"Clash 处理异常: {e}")

def process_json(data: str):
    try:
        content = json.loads(data)
        
        # 原有 hysteria 处理
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str):
                servers = [servers]
           
            has_hop = any(',' in str(s) and '-' in str(s) for s in servers)
            typ = "hysteria2" if has_hop or "hysteria2" in str(content).lower() else "hysteria"
           
            for s in servers:
                if not s: continue
                server, main_port, ports_range = parse_server_port(s)
                name_suffix = f" ({ports_range})" if ports_range else ""
                
                tls_cfg = content.get('tls', {})
                sni_val = content.get('sni') or content.get('peer') or content.get('server_name') or tls_cfg.get('sni', '')

                if typ == "hysteria":
                    alpn = content.get('alpn')
                    if isinstance(alpn, str): alpn = [alpn]
                    elif not alpn: alpn = ["h3"]
                        
                    auth = content.get('auth_str') or content.get('auth') or content.get('password', '')
                    p = {
                        "name": f"{get_location(server)}-{typ.upper()}-{len(extracted_proxies)+1}{name_suffix}",
                        "type": typ,
                        "server": server,
                        "port": main_port,
                        "auth-str": auth,
                        "auth_str": auth,   # 增加兼容别名
                        "sni": sni_val,
                        "skip-cert-verify": content.get('insecure', tls_cfg.get('insecure', True)),
                        "alpn": alpn,
                        "protocol": content.get('protocol', 'udp'),
                        "up": parse_bw(content.get('up_mbps') or content.get('upmbps') or content.get('up')),
                        "down": parse_bw(content.get('down_mbps') or content.get('downmbps') or content.get('down')),
                    }
                else:
                    auth = content.get('auth') or content.get('password', content.get('auth_str', ''))
                    p = {
                        "name": f"{get_location(server)}-{typ.upper()}-{len(extracted_proxies)+1}{name_suffix}",
                        "type": typ,
                        "server": server,
                        "port": main_port,
                        "password": auth,
                        "auth": auth,       # 增加兼容别名
                        "sni": sni_val,
                        "skip-cert-verify": content.get('insecure', tls_cfg.get('insecure', True)),
                        "alpn": content.get('alpn', ["h3"]),
                    }
                
                if ports_range:
                    p['ports'] = ports_range
                
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)

        # vless 加强处理
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): continue
            proto = (ob.get('protocol') or ob.get('type') or '').lower()
            if proto != 'vless': continue
            
            settings = ob.get('settings', ob)
            vnext = settings.get('vnext', [{}])[0]
            server = vnext.get('address')
            if not server: continue
            port = int(vnext.get('port', 443))
            
            user = vnext.get('users', [{}])[0]
            stream = ob.get('streamSettings', {})
            reality = stream.get('realitySettings', {}) or stream.get('tlsSettings', {})

            p = {
                "name": f"{get_location(server)}-VLESS-{len(extracted_proxies)+1}",
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": user.get('id'),
                "flow": user.get('flow', ''),
                "network": stream.get('network', 'tcp'),
                "tls": stream.get('security') in ('tls', 'reality', 'xtls'),
                "sni": reality.get('serverName') or stream.get('serverName') or '',
                "client-fingerprint": reality.get('fingerprint', 'chrome'),
                "alpn": reality.get('alpn', ["h3"]),
            }

            if stream.get('security') == 'reality':
                p['reality-opts'] = {
                    "public-key": reality.get('publicKey', ''),
                    "short-id": reality.get('shortId', '')
                }

            if stream.get('network') == 'ws':
                ws = stream.get('wsSettings', {})
                headers = ws.get('headers', {})
                if not headers and p.get('sni'):
                    headers = {"Host": p.get('sni')}
                p['ws-opts'] = {
                    "path": ws.get('path', '/'),
                    "headers": headers
                }

            elif stream.get('network') == 'xhttp':
                xhttp = stream.get('xhttpSettings', {})
                p['xhttp-opts'] = {
                    "path": xhttp.get('path', '/'),
                    "mode": xhttp.get('mode', 'auto')
                }
                extra = xhttp.get('extra', {})
                if extra:
                    p['xhttp-opts']['extra'] = extra

            elif stream.get('network') == 'grpc':
                p['grpc-opts'] = {
                    "grpc-service-name": stream.get('grpcSettings', {}).get('serviceName', '')
                }

            p = {k: v for k, v in p.items() if v not in (None, '', {}, [])}
            
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
                
    except Exception as e:
        logger.error(f"JSON 处理异常: {e}")

def parse_server_port(srv):
    srv = str(srv).strip()
    ports_range = None
    if ',' in srv:
        parts = [p.strip() for p in srv.split(',')]
        main_part = parts[0]
        if len(parts) > 1 and '-' in parts[-1]:
            ports_range = parts[-1]
        srv = main_part
    if srv.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', srv)
        if m:
            return m.group(1), int(m.group(2)), ports_range
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1]), ports_range
    return srv, 443, ports_range

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    logger.info("=== ChromeGo Enhanced v3.5.2 终极修复加强版启动 ===")
    process_file("urls/sources.txt")
    logger.info(f"最终共提取 {len(extracted_proxies)} 个唯一节点")
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)
    logger.info("✅ 输出完成！ 输出文件 → outputs/clash_meta.yaml")
