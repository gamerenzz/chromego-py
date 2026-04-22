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
import socket
from urllib.parse import urlparse, parse_qs

# ==================== YAML 渲染器极致修正 (解决排序问题) ====================
class PureDumper(yaml.SafeDumper):
    def represent_mapping(self, tag, mapping, flow_style=None):
        # 强制不排序，保持代码中的插入顺序
        return super(PureDumper, self).represent_mapping(tag, mapping, flow_style=flow_style)

# 强制所有字典在输出时使用单行流式格式，且不排序
def dict_representer(dumper, data):
    return dumper.represent_mapping('tag:yaml.org,2002:map', data.items(), flow_style=True)

yaml.add_representer(dict, dict_representer, Dumper=PureDumper)

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
            p = dict(p)
            p_type = str(p.get('type','')).lower()
            auth = p.get('auth-str') or p.get('auth_str') or p.get('password') or ''
            
            # 【核心对齐】严格按照网友通畅版的字段顺序和内容
            node = {"name": f"{get_location(p.get('server'))}-{p_type.upper()}-{len(extracted_proxies)+1}"}
            node["server"] = p.get('server').strip('[]')
            node["port"] = int(p.get('port'))
            node["type"] = p_type
            
            if p_type == 'hysteria':
                node.update({
                    "auth_str": auth, "auth-str": auth,
                    "up": 100, "down": 100, # 对齐网友，强制 100 以提高成功率
                    "fast-open": False, "skip-cert-verify": True, "alpn": ['h3']
                })
            elif p_type == 'hysteria2':
                node.update({
                    "password": auth, "auth": auth, "sni": p.get('sni', 'www.bing.com'),
                    "skip-cert-verify": False, "alpn": ['h3']
                })
            elif p_type == 'tuic':
                node.update({
                    "uuid": p.get('uuid'), "password": auth,
                    "skip-cert-verify": False, "alpn": ['h3'], "udp-relay-mode": "native", "congestion-controller": "bbr"
                })
            else:
                for k, v in p.items():
                    if k not in node: node[k] = v

            fp = make_fingerprint(node)
            if fp not in servers_list:
                extracted_proxies.append(node)
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
                
                node = {"name": f"{get_location(host)}-{typ.upper()}-{len(extracted_proxies)+1}"}
                node["server"] = host.strip('[]')
                node["port"] = int(port)
                node["type"] = typ
                
                if typ == "hysteria":
                    node.update({
                        "auth_str": auth, "auth-str": auth,
                        "up": 100, "down": 100, "fast-open": False, "skip-cert-verify": True, "alpn": ['h3']
                    })
                else:
                    node.update({
                        "password": auth, "auth": auth, "sni": content.get('sni') or 'www.bing.com',
                        "skip-cert-verify": False, "alpn": ['h3']
                    })

                fp = make_fingerprint(node)
                if fp not in servers_list:
                    extracted_proxies.append(node)
                    servers_list.append(fp)
        
        # VLESS 逻辑排序对齐
        for ob in content.get('outbounds', []):
            if not isinstance(ob, dict): continue
            if (ob.get('protocol') or ob.get('type') or '').lower() == 'vless':
                vnext = ob.get('settings', {}).get('vnext', [{}])[0]
                server = vnext.get('address')
                if not server: continue
                stream = ob.get('streamSettings', {})
                reality = stream.get('realitySettings', {}) or stream.get('tlsSettings', {})
                network = stream.get('network', 'tcp')
                
                node = {"name": f"{get_location(server)}-VLESS-{len(extracted_proxies)+1}"}
                node.update({
                    "server": server, "port": int(vnext.get('port', 443)), "type": "vless",
                    "uuid": vnext.get('users', [{}])[0].get('id'), "network": network, "tls": True,
                    "sni": reality.get('serverName', 'www.bing.com'), "alpn": ['h3'], "skip-cert-verify": False
                })
                if network == 'tcp': node['flow'] = vnext.get('users', [{}])[0].get('flow', '')
                if stream.get('security') == 'reality':
                    node['reality-opts'] = {"public-key": reality.get('publicKey', ''), "short-id": reality.get('shortId', '')}
                if network == 'xhttp':
                    node['xhttp-opts'] = {"path": stream.get('xhttpSettings', {}).get('path', '/'), "mode": "auto"}

                fp = make_fingerprint(node)
                if fp not in servers_list:
                    extracted_proxies.append(node)
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
        f.write("proxies:\n")
        for proxy in extracted_proxies:
            # 使用 Dumper=PureDumper 强制执行我们自定义的“不排序、单行、name 领先”逻辑
            yaml_str = yaml.dump(proxy, Dumper=PureDumper, allow_unicode=True, sort_keys=False, width=float("inf"))
            f.write(f"  - {yaml_str.strip()}\n")
    print(f"✅ 提取完成，共 {len(extracted_proxies)} 个节点")
