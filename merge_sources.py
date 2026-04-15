import urllib.request
import os
from urllib.error import URLError, HTTPError

def fetch_url(url: str) -> str:
    """
    读取订阅地址内容（支持直接访问的链接和需要下载的链接）
    统一使用带 User-Agent 的请求，防止部分站点拒绝默认 Python UA
    """
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
            }
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            if response.getcode() == 200:
                content = response.read().decode('utf-8', errors='replace')
                return content
            else:
                return f"# 【错误】HTTP {response.getcode()} - {url}\n"
    except (URLError, HTTPError) as e:
        return f"# 【错误】无法访问 {url}：{str(e)}\n"
    except Exception as e:
        return f"# 【错误】未知异常 {url}：{str(e)}\n"


def main():
    input_file = "urls/sources.txt"
    output_file = "merged_subscriptions.txt"

    # 检查文件是否存在
    if not os.path.exists(input_file):
        print(f"❌ 未找到 {input_file} 文件！请确保该文件在脚本同目录下。")
        return

    # 解析 urls/sources.txt（按空行分组）
    groups = []
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    current_group = None
    current_urls = []

    for line in lines:
        if line.strip() == "":  # 空行 = 分组结束
            if current_group is not None and current_urls:
                groups.append((current_group, current_urls[:]))
                current_urls = []
            current_group = None
            continue

        # 新的分组标识（每组第一行）
        if current_group is None:
            current_group = line.rstrip()   # 保留原始格式（含中文和空格）
            current_urls = []
        else:
            # 订阅地址（去除首尾空格）
            url = line.strip()
            if url:  # 防止空行被误判
                current_urls.append(url)

    # 处理最后一个分组
    if current_group is not None and current_urls:
        groups.append((current_group, current_urls[:]))

    print(f"✅ 共解析到 {len(groups)} 个分组，开始下载订阅内容...\n")

    # 开始合并写入
    with open(output_file, "w", encoding="utf-8") as out:
        out.write("# =======================\n")
        out.write("# 合并后的订阅文件\n")
        out.write("# 由 merge_sources.py 自动生成\n")
        out.write("# 生成时间：自动\n")
        out.write("# =======================\n\n")

        total_fetched = 0
        for group_id, urls in groups:
            print(f"📂 处理分组：{group_id}  ({len(urls)} 个地址)")
            for url in urls:
                print(f"   ⬇️  正在下载 → {url}")
                content = fetch_url(url)
                total_fetched += 1

                # 每一段内容前插入分组标识（严格按照题目要求）
                out.write(f"{group_id}\n")
                out.write(content)
                out.write("\n\n")   # 两个空行分隔不同订阅内容，便于阅读

        print(f"\n🎉 全部完成！共处理 {total_fetched} 个订阅地址")
        print(f"📄 输出文件：{output_file}（已保存到当前目录）")


if __name__ == "__main__":
    main()
