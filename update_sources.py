import re
from pathlib import Path
from collections import defaultdict

def extract_subscription_urls(bat_content: str) -> list[str]:
    """原提取逻辑（你确认没问题）"""
    urls = []
    pattern = re.compile(r'https?://[^\s<>"\']+\.(?:yaml|json|yml)', re.IGNORECASE)
    
    matches = pattern.findall(bat_content)
    for match in matches:
        url = match.strip('"\' ')
        if url.startswith(('http://', 'https://')):
            urls.append(url)
    
    # 去重保持顺序
    seen = set()
    unique_urls = [url for url in urls if not (url in seen or seen.add(url))]
    return unique_urls


def process_folder(top_folder: str, root_dir: Path) -> dict:
    """处理单个客户端文件夹"""
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
            
        print(f"  → 处理分组: {group_name}  (找到 {len(bat_files)} 个 .bat 文件)")
        
        group_urls_count = 0
        for bat_file in bat_files:
            try:
                content = bat_file.read_text(encoding="utf-8", errors="ignore")
                urls = extract_subscription_urls(content)
                if urls:
                    groups[group_name].extend(urls)
                    group_urls_count += len(urls)
                    print(f"     • {bat_file.name}  →  提取到 {len(urls)} 条")
                # else:
                #     print(f"     • {bat_file.name}  →  未提取到地址")
            except Exception as e:
                print(f"    读取失败 {bat_file.name}: {e}")
        
        if group_urls_count > 0:
            print(f"     → {group_name} 本次共提取 {group_urls_count} 条地址")
    
    # 分组内去重（关键修复：确保这里正确处理）
    final_groups = {}
    for group_name, url_list in groups.items():
        seen = set()
        unique_urls = []
        for url in url_list:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        if unique_urls:
            final_groups[group_name] = unique_urls
            print(f"     → 分组 {group_name} 去重后保留 {len(unique_urls)} 条")
    
    return final_groups


def write_sources_file(groups: dict, filepath: Path):
    """强制写入文件"""
    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        if not groups:
            f.write("# 无有效订阅地址\n")
            print(f"   → {filepath.name} 写入：无有效地址")
            return
        
        first = True
        total_written = 0
        for group_name in sorted(groups.keys()):
            if not first:
                f.write("\n")
            f.write(f"# {group_name}\n")
            for url in groups[group_name]:
                f.write(url + "\n")
                total_written += 1
            first = False
        
        print(f"   → {filepath.name} 写入完成：{len(groups)} 个分组，共 {total_written} 条地址")


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
        
        # 收集用于合并
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
    
    print("\n" + "="*80)
    print("🎉 全部处理完成！请检查 urls/ 目录下 4 个文件是否已有内容。")
    print("="*80)


if __name__ == "__main__":
    main()
