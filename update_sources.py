import re
from pathlib import Path
from collections import defaultdict

def extract_subscription_urls(bat_content: str) -> list[str]:
    """你原来的提取逻辑（保持不变）"""
    urls = []
    pattern = re.compile(r'https?://[^\s<>"\']+\.(?:yaml|json|yml)', re.IGNORECASE)
    
    matches = pattern.findall(bat_content)
    for match in matches:
        url = match.strip('"\' ')
        if url.startswith(('http://', 'https://')):
            urls.append(url)
    
    seen = set()
    unique_urls = [url for url in urls if not (url in seen or seen.add(url))]
    return unique_urls


def process_folder(top_folder: str, root_dir: Path) -> dict:
    groups = defaultdict(list)
    top_path = root_dir / top_folder
    
    if not top_path.exists() or not top_path.is_dir():
        print(f"⚠️  文件夹不存在，跳过: {top_folder}")
        return {}
    
    print(f"\n开始处理 → {top_folder}")
    
    for ip_update_dir in top_path.rglob("ip_Update"):
        if not ip_update_dir.is_dir():
            continue
        group_name = ip_update_dir.parent.name
        bat_files = list(ip_update_dir.glob("*.bat"))
        
        if not bat_files:
            continue
            
        print(f"  → 处理 {group_name}  (找到 {len(bat_files)} 个 .bat 文件)")
        
        for bat_file in bat_files:
            try:
                content = bat_file.read_text(encoding="utf-8", errors="ignore")
                urls = extract_subscription_urls(content)
                if urls:
                    groups[group_name].extend(urls)
            except Exception as e:
                print(f"    读取失败 {bat_file.name}: {e}")
    
    # 分组内去重
    final_groups = {}
    for group_name, url_list in groups.items():
        seen = set()
        unique_urls = [url for url in url_list if not (url in seen or seen.add(url))]
        if unique_urls:
            final_groups[group_name] = unique_urls
    
    return final_groups


def write_sources_file(groups: dict, filepath: Path, header: str = ""):
    """写入文件（强制覆盖，确保文件被修改）"""
    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        if header:
            f.write(header + "\n\n")
        
        if not groups:
            f.write("# 无有效订阅地址\n")
            return
        
        first = True
        for group_name in sorted(groups.keys()):
            if not first:
                f.write("\n")
            f.write(f"# {group_name}\n")
            for url in groups[group_name]:
                f.write(url + "\n")
            first = False


def main():
    root_dir = Path.cwd()
    output_dir = root_dir / "urls"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    clients = ["EdgeGo", "ChromeGo", "FirefoxFQ"]
    all_groups = defaultdict(list)
    
    print("=== 开始提取订阅地址 ===\n")
    
    for client in clients:
        groups = process_folder(client, root_dir)
        
        client_file = output_dir / f"{client}_sources.txt"
        write_sources_file(groups, client_file)
        
        if groups:
            total = sum(len(u) for u in groups.values())
            print(f"✅ {client}_sources.txt 已生成（{len(groups)} 个分组，{total} 条地址）")
        else:
            print(f"✅ {client}_sources.txt 已生成（无数据）")
        
        for g, urls in groups.items():
            all_groups[g].extend(urls)
    
    # 生成最终 sources.txt
    final_groups = {}
    for group_name, url_list in all_groups.items():
        seen = set()
        unique = [url for url in url_list if not (url in seen or seen.add(url))]
        if unique:
            final_groups[group_name] = unique
    
    final_file = output_dir / "sources.txt"
    write_sources_file(final_groups, final_file)
    
    print("\n🎉 全部完成！已在 urls/ 下生成 4 个文件（sources.txt 已强制写入）")


if __name__ == "__main__":
    main()
