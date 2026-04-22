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
import urllib.parse

# ==================== YAML 渲染器 ====================
class PureDumper(yaml.SafeDumper):
    def represent_mapping(self, tag, mapping, flow_style=None):
        return super(PureDumper, self).represent_mapping(tag, mapping, flow_style=flow_style)

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
try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    logger.warning("GeoLite2-City.mmdb 未找到")

# ==================== 工具函数 ====================
def get_flag(code: str) -> str:
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
        return f"{flag}{c}-{resp.city.name or ''}".strip('-')
    except:
        return "UNK"

def parse_bw_int(val) -> int:
    if not val:
        return 100
    m = re.search(r'(\d+)', str(val))
    return int(m.group(1)) if m else 100

def make_fingerprint(p: dict) -> str:
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|{p.get('uuid') or p.get('password') or p.get('auth-str','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def normalize_alpn(alpn_val):
    if alpn_val is None:
        return ['h3']
    if isinstance(alpn_val, str):
        return [alpn_val]
    if isinstance(alpn_val, list):
        return alpn_val
    return ['h3']

# ====================== 核心解析 ======================
def process_clash(data: str):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])

        for p in proxies:
            if not isinstance(p, dict) or not p.get('server'):
                continue

            p = dict(p)
            p_type = str(p.get('type', '')).lower()

            node = dict(p)  # ✅ 保留原始字段（关键）
            node["server"] = p.get('server').strip('[]')
            node["port"] = int(p.get('port'))
            node["type"] = p_type

            # 统一 alpn
            node["alpn"] = normalize_alpn(p.get("alpn"))

            # ===== 特殊协议修正 =====
            if p_type == 'hysteria':
                node["auth_str"] = p.get('auth_str') or p.get('auth-str') or p.get('auth') or ''
                node["auth-str"] = node["auth_str"]

                node["up"] = parse_bw_int(p.get('up'))
                node["down"] = parse_bw_int(p.get('down'))

                # ✅ 关键：补 protocol
                node["protocol"] = p.get("protocol", "udp")

            elif p_type == 'hysteria2':
                node["password"] = p.get('password') or p.get('auth') or ''
                node["auth"] = node["password"]

                # ❗ 不乱加默认 sni
                if p.get("sni"):
                    node["sni"] = p.get("sni")

            elif p_type == 'tuic':
                node["password"] = p.get('password') or ''
                node["uuid"] = p.get('uuid')

            # 生成 name
            node["name"] = f"{get_location(node['server'])}-{p_type.upper()}-{len(extracted_proxies)+1}"

            # 去重
            fp = make_fingerprint(node)
            if fp not in servers_list:
                extracted_proxies.append(node)
                servers_list.append(fp)

    except Exception as e:
        logger.debug(f"process_clash error: {e}")

# ====================== JSON 解析 ======================
def process_json(data: str):
    try:
        content = json.loads(data)

        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str):
                servers = [servers]

            is_h2 = "hysteria2" in str(content).lower() or 'password' in content
            typ = "hysteria2" if is_h2 else "hysteria"

            for s in servers:
                if not s:
                    continue

                main_addr = str(s).split(',')[0]
                ports_hopping = str(s).split(',')[1] if ',' in str(s) else None

                host, port = (main_addr.rsplit(':', 1) if ':' in main_addr else (main_addr, 443))

                node = {
                    "server": host.strip('[]'),
                    "port": int(port),
                    "type": typ,
                    "name": f"{get_location(host)}-{typ.upper()}-{len(extracted_proxies)+1}"
                }

                node["alpn"] = normalize_alpn(content.get("alpn"))

                if typ == "hysteria":
                    node.update({
                        "auth_str": content.get('auth_str') or '',
                        "auth-str": content.get('auth_str') or '',
                        "up": parse_bw_int(content.get('up')),
                        "down": parse_bw_int(content.get('down')),
                        "protocol": "udp",
                        "skip-cert-verify": content.get('skip-cert-verify', True)
                    })
                else:
                    node.update({
                        "password": content.get('password') or '',
                        "auth": content.get('password') or '',
                        "skip-cert-verify": content.get('skip-cert-verify', True)
                    })
                    if content.get("sni"):
                        node["sni"] = content.get("sni")

                if ports_hopping:
                    node['ports'] = ports_hopping

                fp = make_fingerprint(node)
                if fp not in servers_list:
                    extracted_proxies.append(node)
                    servers_list.append(fp)

    except Exception as e:
        logger.debug(f"process_json error: {e}")

# ====================== 下载入口 ======================
def process_file(file_path: str):
    with open(file_path, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode('utf-8', errors='ignore')

            if 'proxies:' in raw or 'proxy:' in raw:
                process_clash(raw)
            else:
                process_json(raw)

        except Exception as e:
            logger.warning(f"下载失败 {url}: {e}")

# ====================== 主程序 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    process_file("urls/sources.txt")

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        f.write("proxies:\n")
        for proxy in extracted_proxies:
            yaml_str = yaml.dump(proxy, Dumper=PureDumper, allow_unicode=True, sort_keys=False, width=float("inf"))
            f.write(f"  - {yaml_str.strip()}\n")

    print(f"✅ 完成，共 {len(extracted_proxies)} 个节点")
