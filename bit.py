import sys
import time
from pathlib import Path

def count_coverage(data):
    """统计字节数据中置位比特的数量"""
    return sum(bin(byte).count('1') for byte in data)

def merge_content(base_data, new_content):
    """将新内容按位或合并到基础数据中"""
    if len(base_data) < len(new_content):
        base_data.extend(b'\x00' * (len(new_content) - len(base_data)))
    for i in range(len(new_content)):
        base_data[i] |= new_content[i]
    return base_data

def main():
    # 解析命令行参数
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <output_file>")
        sys.exit(1)
    
    output_path = sys.argv[1]  # 从第一个参数获取输出文件路径
    shm_dir = Path('/dev/shm')
    processed_timestamps = set()
    merged_edge = bytearray()
    merged_bitmap = bytearray()
    max_coverage = 0
    start_time = int(time.time())
    
    # 处理输出文件
    output_file = Path(output_path)
    if output_file.exists():
        output_file.rename(output_file.with_name(output_file.name + "_dup"))
    output_file.touch()

    while True:
        new_ts_found = False
        file_groups = {}

        # 扫描所有未处理的覆盖文件
        for fpath in shm_dir.glob('*edge__*'):
            if not fpath.name.startswith('edge__'):
                continue
            
            _, rest = fpath.name.split('__', 1)
            service, ts = rest.split('-', 1)
            if ts in processed_timestamps:
                continue

            bitmap_file = shm_dir / f"bitmap__{service}-{ts}"
            if not bitmap_file.exists():
                continue

            file_groups[ts] = (bitmap_file, fpath)
            processed_timestamps.add(ts)
            new_ts_found = True

        if new_ts_found:
            for ts, (bitmap_path, edge_path) in file_groups.items():
                with open(bitmap_path, 'rb') as f:
                    merged_bitmap = merge_content(merged_bitmap, f.read())
                
                with open(edge_path, 'rb') as f:
                    merged_edge = merge_content(merged_edge, f.read())

            current_cov = count_coverage(merged_edge)
            if current_cov > max_coverage:
                max_coverage = current_cov
                elapsed = int(time.time()) - start_time
                with open(output_file, 'a') as f:
                    f.write(f"{elapsed},{max_coverage}\n")
                print(f"Coverage updated: {max_coverage} at {elapsed}s")

        time.sleep(1)

if __name__ == '__main__':
    main()
