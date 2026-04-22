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

# ================= YAML 渲染 =================
class PureDumper(yaml.SafeDumper):
    pass

def dict_representer(dumper, data):
    return dumper.represent_mapping(
        'tag:yaml.org,2002:map',
        data.items(),
        flow_style=True
    )

yaml.add_representer(dict, dict_representer, Dumper=PureDumper)

# ================= 全局 =================
socket.setdefaulttimeout(15)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)
logger = logging.getLogger("ProxyFix")

servers_list = []
extracted_proxies = []

geo_reader = None
try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    logger.warning("GeoLite2-City.mmdb 未找到")

# ================= 工具函数 =================
def get_flag(code):
    if not code or len(code) != 2:
        return ""
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)

def get_location(ip):
    if not geo_reader:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        code = resp.country.iso_code or "UNK"
        flag = get_flag(code)
        return f"{flag} {code}" if flag else code
    except:
        return "UNK"

def parse_bw_int(val):
    if not val:
        return 100
    m = re.search(r'(\d+)', str(val))
    return int(m.group(1)) if m else 100

def normalize_alpn(v):
    if not v:
        return ["h3"]
    if isinstance(v, str):
        return [v]
    return v

def make_fingerprint(p):
    key = f"{p.get('server')}|{p.get('port')}|{p.get('type')}|{p.get('uuid') or p.get('password') or p.get('auth_str')}"
    return hashlib.md5(key.encode()).hexdigest()

def detect_hysteria_type(content):
    text = str(content).lower()

    if "hysteria2" in text:
        return "hysteria2"
    if "ports" in content:
        return "hysteria2"
    return "hysteria"

def clean_node(node):
    INVALID = {
        "request-timeout",
        "fast-open",
        "tfo",
    }
    for k in list(node.keys()):
        if k in INVALID:
            node.pop(k)

# ================= Clash 解析 =================
def process_clash(data):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])

        for p in proxies:
            if not isinstance(p, dict) or not p.get("server"):
                continue

            p = dict(p)
            typ = str(p.get("type", "")).lower()

            node = dict(p)
            node["server"] = p["server"].strip('[]')
            node["port"] = int(p["port"])
            node["type"] = typ
            node["alpn"] = normalize_alpn(p.get("alpn"))

            # ===== hysteria1 =====
            if typ == "hysteria":
                node["auth_str"] = p.get("auth_str") or p.get("auth-str") or ""
                node["auth-str"] = node["auth_str"]

                if not node["auth_str"]:
                    continue

                node["up"] = parse_bw_int(p.get("up"))
                node["down"] = parse_bw_int(p.get("down"))
                node["protocol"] = "udp"

                # ❗ 删除错误 sni
                node.pop("sni", None)

            # ===== hysteria2 =====
            elif typ == "hysteria2":
                node["password"] = p.get("password") or ""
                node["auth"] = node["password"]

                if not node["password"]:
                    continue

            # ===== tuic =====
            elif typ == "tuic":
                if not p.get("uuid") or not p.get("password"):
                    continue

            # name
            node["name"] = f"{get_location(node['server'])}-{typ.upper()}-{len(extracted_proxies)+1}"

            clean_node(node)

            fp = make_fingerprint(node)
            if fp not in servers_list:
                extracted_proxies.append(node)
                servers_list.append(fp)

    except Exception as e:
        logger.debug(f"clash parse error: {e}")

# ================= JSON 解析 =================
def process_json(data):
    try:
        content = json.loads(data)

        if "server" in content or "servers" in content:
            servers = content.get("server") or content.get("servers")
            if isinstance(servers, str):
                servers = [servers]

            typ = detect_hysteria_type(content)

            for s in servers:
                if not s:
                    continue

                main = str(s).split(",")[0]
                hop = str(s).split(",")[1] if "," in str(s) else None

                host, port = main.rsplit(":", 1) if ":" in main else (main, 443)

                node = {
                    "server": host.strip('[]'),
                    "port": int(port),
                    "type": typ,
                    "alpn": normalize_alpn(content.get("alpn")),
                    "name": f"{get_location(host)}-{typ.upper()}-{len(extracted_proxies)+1}"
                }

                # ===== hysteria1 =====
                if typ == "hysteria":
                    auth = content.get("auth_str") or ""

                    if not auth:
                        continue

                    node.update({
                        "auth_str": auth,
                        "auth-str": auth,
                        "up": parse_bw_int(content.get("up")),
                        "down": parse_bw_int(content.get("down")),
                        "protocol": "udp",
                        "skip-cert-verify": content.get("skip-cert-verify", True)
                    })

                # ===== hysteria2 =====
                else:
                    pwd = content.get("password") or ""

                    if not pwd:
                        continue

                    node.update({
                        "password": pwd,
                        "auth": pwd,
                        "skip-cert-verify": content.get("skip-cert-verify", True)
                    })

                    if content.get("sni"):
                        node["sni"] = content.get("sni")

                    if hop:
                        node["ports"] = f"{port},{hop}"

                clean_node(node)

                fp = make_fingerprint(node)
                if fp not in servers_list:
                    extracted_proxies.append(node)
                    servers_list.append(fp)

    except Exception as e:
        logger.debug(f"json parse error: {e}")

# ================= 下载 =================
def process_file(path):
    with open(path, "r", encoding="utf-8") as f:
        urls = [x.strip() for x in f if x.strip() and not x.startswith("#")]

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            raw = urllib.request.urlopen(req).read().decode("utf-8", "ignore")

            if "proxies:" in raw:
                process_clash(raw)
            else:
                process_json(raw)

        except Exception as e:
            logger.warning(f"下载失败: {url} | {e}")

# ================= 主程序 =================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    process_file("urls/sources.txt")

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        f.write("proxies:\n")
        for p in extracted_proxies:
            y = yaml.dump(p, Dumper=PureDumper, allow_unicode=True, sort_keys=False, width=float("inf"))
            f.write(f"  - {y.strip()}\n")

    print(f"✅ 完成，共 {len(extracted_proxies)} 个节点")
