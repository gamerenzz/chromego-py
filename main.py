#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
ChromeGo Enhanced v3.5.1 - 纯 Y 系列版（vless Reality + WS/xhttp 最终加强版）
- 修复 节点名称重复导致的 Clash Meta 解析失败问题
- 修复 vless xhttp 配置提取缺失问题
- 修复 Hysteria1 带宽字段 (up_mbps) 提取失败问题
- 修复 Hysteria2 SNI 字段提取失败问题
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
import time
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

def get_location(ip: str) -> str:
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{c}-{city}" if city else c
    except:
        return "UNK"

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

                # 处理 vless:// 直链
                lines = [line.strip() for line in processed_data.splitlines() if line.strip()]
                for line in lines:
                    if line.startswith('vless://'):
                        proxy = parse_vless_link(line)
                        if proxy:
                            fp = make_fingerprint(proxy)
                            if fp not in servers_list:
                                extracted_proxies.append(proxy)
                                servers_list.append(fp)

                # 原有 Clash / JSON 处理
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
            fp = make_fingerprint(p)
            if fp in servers_list:
                continue
           
            original_name = p.get('name', '')
            # 【修复1】严格使用全局长度防止节点重名
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
                
                # 【修复4】深层获取 SNI (适配 Hysteria2 JSON)
                tls_cfg = content.get('tls', {})
                sni_val = content.get('sni') or content.get('peer') or content.get('server_name') or tls_cfg.get('sni', '')

                if typ == "hysteria":
                    alpn = content.get('alpn')
                    if isinstance(alpn, str):
                        alpn = [alpn]
                    elif not alpn:
                        alpn = ["h3"]
                        
                    p = {
                        # 【修复1】使用 len(extracted_proxies)+1 防重名
                        "name": f"{get_location(server)}-{typ.upper()}-{len(extracted_proxies)+1}{name_suffix}",
                        "type": typ,
                        "server": server,
                        "port": main_port,
                        "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                        "auth-str": content.get('auth_str') or content.get('auth') or content.get('password', ''),
                        "sni": sni_val,
                        "skip-cert-verify": content.get('insecure', tls_cfg.get('insecure', True)),
                        "alpn": alpn,
                        # 【修复3】兼容官方的 up_mbps 写法
                        "up": content.get('up_mbps') or content.get('upmbps') or content.get('up') or 100,
                        "down": content.get('down_mbps') or content.get('downmbps') or content.get('down') or 100,
                    }
                else:
                    p = {
                        "name": f"{get_location(server)}-{typ.upper()}-{len(extracted_proxies)+1}{name_suffix}",
                        "type": typ,
                        "server": server,
                        "port": main_port,
                        "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
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

        # ==================== vless 加强处理 ====================
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

            # Reality 关键字段
            if stream.get('security') == 'reality':
                p['reality-opts'] = {
                    "public-key": reality.get('publicKey', ''),
                    "short-id": reality.get('shortId', '')
                }

            # WS 配置加强
            if stream.get('network') == 'ws':
                ws = stream.get('wsSettings', {})
                headers = ws.get('headers', {})
                if not headers and p.get('sni'):
                    headers = {"Host": p.get('sni')}
                p['ws-opts'] = {
                    "path": ws.get('path', '/'),
                    "headers": headers
                }

            # 【修复2】新增 xhttp 配置加强 (核心补丁)
            elif stream.get('network') == 'xhttp':
                xhttp = stream.get('xhttpSettings', {})
                p['xhttp-opts'] = {
                    "path": xhttp.get('path', '/'),
                    "mode": xhttp.get('mode', 'auto')
                }
                extra = xhttp.get('extra', {})
                if extra:
                    p['xhttp-opts']['extra'] = extra

            # gRPC 配置
            elif stream.get('network') == 'grpc':
                p['grpc-opts'] = {
                    "grpc-service-name": stream.get('grpcSettings', {}).get('serviceName', '')
                }

            # 清理空值 (避免 Clash Meta 解析到空 flow 报错)
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
    logger.info("=== ChromeGo Enhanced v3.5.1 最终修复加强版启动 ===")
    process_file("urls/sources.txt")
    logger.info(f"最终共提取 {len(extracted_proxies)} 个唯一节点")
    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False)
    logger.info("✅ 输出完成！ 输出文件 → outputs/clash_meta.yaml")
