# -*- coding: UTF-8 -*-
"""
最终增强版 - 2026 最新规则支持 + 完美兼容原始混乱订阅 + 提取更多可用节点
"""

import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import hashlib
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

servers_list = []      # 指纹去重
extracted_proxies = []
geo_reader = None

try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception:
    logging.warning("GeoLite2-City.mmdb 未找到，位置将显示 UNK")

def get_location(ip):
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{c}-{city.replace(' ', '')}" if city else c
    except:
        return "UNK"

def make_fingerprint(p):
    """更全面的去重指纹，包含 uuid、网络、路径等关键字段"""
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|{p.get('password') or p.get('auth_str','') or p.get('uuid','')}|{p.get('network','')}|{p.get('path','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def normalize_proxy(p: dict) -> dict:
    """核心标准化函数：依据原始文件字段 + 最新规则"""
    p = dict(p)  # 复制避免修改原数据

    typ = p.get('type', '').lower()

    # 1. Hysteria1 / Hysteria2 字段统一
    if typ == 'hysteria':
        p['auth_str'] = p.pop('password', None) or p.pop('auth-str', None) or p.get('auth_str', '')
        p.setdefault('alpn', ['h3'])
        p['up'] = f"{p.get('up', 100)} Mbps"
        p['down'] = f"{p.get('down', 100)} Mbps"
    elif typ == 'hysteria2':
        p['password'] = p.pop('auth_str', None) or p.pop('auth-str', None) or p.pop('password', '')
        p.setdefault('alpn', ['h3'])
        p['up'] = f"{p.get('up', 55)} Mbps"
        p['down'] = f"{p.get('down', 55)} Mbps"
        # 新增 2026 支持：obfs、hop-interval
        if p.get('obfs') or p.get('obfs-password'):
            p.setdefault('obfs', 'salamander')

    # 2. alpn 强制转列表
    if isinstance(p.get('alpn'), str):
        p['alpn'] = [p['alpn']]

    # 3. VLESS Reality 最新规则
    if typ == 'vless':
        p.setdefault('udp', True)
        p.setdefault('client-fingerprint', 'chrome')
        # reality 对象转 reality-opts
        if 'reality' in p:
            reality = p.pop('reality')
            p['reality-opts'] = {
                'public-key': reality.get('public-key') or reality.get('public_key'),
                'short-id': reality.get('short-id') or reality.get('short_id', '')
            }
        if 'reality-opts' in p:
            p.setdefault('flow', 'xtls-rprx-vision')
        # smux + brutal-opts（原始文件中常见）
        if 'smux' not in p:
            p['smux'] = {'enabled': True, 'protocol': 'h2mux', 'max-connections': 1, 'min-streams': 4, 'padding': True}
            p.setdefault('brutal-opts', {'enabled': True, 'up': 50, 'down': 100})

    # 4. TUIC 最新规则
    if typ == 'tuic':
        p.setdefault('alpn', ['h3'])
        p.setdefault('udp-relay-mode', 'native')
        p.setdefault('congestion-controller', 'bbr')
        p.setdefault('skip-cert-verify', True)

    # 5. 通用最新规则（2026 mihomo 推荐）
    p.setdefault('skip-cert-verify', True)
    p.setdefault('udp', True)
    if p.get('tls') is True or p.get('network') in ('tcp', 'ws', 'httpupgrade'):
        p.setdefault('client-fingerprint', 'chrome')

    # 6. 端口跳跃统一为 ports
    if 'portRange' in p or 'ports' in p:
        p['ports'] = p.pop('portRange', None) or p.get('ports')

    return p

def process_file(file_path, prefix):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=25) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')

                if url.endswith(('.yaml', '.yml')):
                    process_clash(data, prefix)
                else:
                    process_json(data, prefix)

                logging.info(f"✓ {prefix}系列 处理完成: {url}")
            except Exception as e:
                logging.error(f"✗ {prefix}系列 处理失败 {url}: {e}")
    except Exception as e:
        logging.error(f"读取 {file_path} 失败: {e}")

def process_clash(data, prefix):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for i, raw in enumerate(proxies):
            if not isinstance(raw, dict) or not raw.get('server'):
                continue
            p = normalize_proxy(raw)
            fp = make_fingerprint(p)
            if fp in servers_list:
                continue
            p['name'] = f"{prefix}{get_location(p.get('server'))}-{p.get('type','unk').upper()}-{i+1}"
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logging.error(f"Clash 处理异常: {e}")

def process_json(data, prefix):
    try:
        content = json.loads(data)
        # 支持 sing-box / v2ray 风格 outbounds
        outbounds = content.get('outbounds', []) or content.get('server', []) or content.get('servers', [])
        if isinstance(outbounds, (str, dict)):
            outbounds = [outbounds]

        for i, ob in enumerate(outbounds):
            if not isinstance(ob, dict):
                continue
            typ = (ob.get('type') or ob.get('protocol') or '').lower()
            if typ not in ('hysteria', 'hysteria2', 'vless', 'vmess', 'tuic', 'trojan', 'shadowsocks'):
                continue

            p = normalize_proxy(ob)
            p['type'] = typ

            # sing-box 常见字段映射
            p.setdefault('server', ob.get('server') or ob.get('address'))
            p.setdefault('port', ob.get('port') or ob.get('server_port', 443))
            p.setdefault('password', ob.get('password') or ob.get('users', [{}])[0].get('password'))
            p.setdefault('uuid', ob.get('uuid') or ob.get('users', [{}])[0].get('id'))

            fp = make_fingerprint(p)
            if fp not in servers_list:
                p['name'] = f"{prefix}{get_location(p.get('server'))}-{typ.upper()}-{i+1}"
                extracted_proxies.append(p)
                servers_list.append(fp)

    except Exception as e:
        logging.error(f"JSON 处理异常: {e}")

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    logging.info("=== 开始提取节点（2026 增强版） ===")
    
    process_file("urls/sources.txt", "Y-")
    process_file("urls/sources-j.txt", "Z-")

    logging.info(f"总共提取到 {len(extracted_proxies)} 个有效节点（已自动标准化最新规则）")

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": extracted_proxies}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    logging.info("✅ clash_meta.yaml 已生成！可直接导入 Clash Meta / Verge Rev")
