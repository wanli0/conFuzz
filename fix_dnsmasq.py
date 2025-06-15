import re
import subprocess
import os
import sys

def fix_dnsmasq_config(config_path):
    dnsmasq_cmd = [
        '/usr/local/sbin/dnsmasq',
        '-p', '5353',
        '-d',
        '-C', config_path
    ]
    
    max_attempts = 50
    attempts = 0
    
    while attempts < max_attempts:
        attempts += 1
        print(f"Attempt {attempts}: Testing configuration...")
        
        process = subprocess.run(
            dnsmasq_cmd,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )
        
        if process.returncode == 0:
            print("Configuration is valid. Success!")
            return True
        
        stderr = process.stderr.strip()
        if not stderr:
            print("Unknown error occurred. Exiting.")
            return False
        
        print(f"Error encountered: {stderr}")
        
        # 错误处理逻辑
        handled = False
        
        # 1. 处理有行号的错误
        line_error = re.search(r'at line (\d+)', stderr)
        if line_error:
            line_num = int(line_error.group(1))
            print(f"Deleting line {line_num} due to error")
            delete_config_line(config_path, line_num)
            handled = True
        
        # 2. 处理没有行号但有关键信息的错误
        elif re.search(r'cannot read|recompile with|unknown option|bad option|cannot access directory', stderr):
            # 提取错误关键词
            error_keywords = re.findall(r'"(.*?)"|\b(\w+)\b', stderr)
            keywords = [kw for tup in error_keywords for kw in tup if kw]
            
            # 尝试匹配并删除相关行
            for keyword in keywords:
                if delete_config_lines_containing(config_path, keyword):
                    print(f"Deleted lines containing keyword: {keyword}")
                    handled = True
                    break
        
        # 3. 如果以上方法未处理，删除最后一行作为回退
        if not handled:
            print("No specific error location found. Deleting last line.")
            delete_last_config_line(config_path)
    
    print("Reached maximum attempts without fixing configuration.")
    return False

def delete_config_line(config_path, line_num):
    """删除指定行号的行"""
    with open(config_path, 'r') as f:
        lines = f.readlines()
    
    if 1 <= line_num <= len(lines):
        print(f"Deleting line {line_num}: {lines[line_num-1].strip()}")
        del lines[line_num-1]
        
        with open(config_path, 'w') as f:
            f.writelines(lines)
        return True
    
    print(f"Invalid line number: {line_num}")
    return False

def delete_config_lines_containing(config_path, pattern):
    """删除包含特定模式的行"""
    with open(config_path, 'r') as f:
        lines = f.readlines()
    
    new_lines = []
    deleted = False
    
    for line in lines:
        if pattern in line:
            print(f"Deleting line containing '{pattern}': {line.strip()}")
            deleted = True
        else:
            new_lines.append(line)
    
    if deleted:
        with open(config_path, 'w') as f:
            f.writelines(new_lines)
        return True
    
    print(f"Pattern '{pattern}' not found in config")
    return False

def delete_last_config_line(config_path):
    """删除最后一行"""
    with open(config_path, 'r') as f:
        lines = f.readlines()
    
    if lines:
        print(f"Deleting last line: {lines[-1].strip()}")
        with open(config_path, 'w') as f:
            f.writelines(lines[:-1])
        return True
    
    print("Config file is empty")
    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fix_dnsmasq.py <config_path>")
        sys.exit(1)
    
    config_file = sys.argv[1]
    if not os.path.isfile(config_file):
        print(f"Config file not found: {config_file}")
        sys.exit(1)
    
    print(f"Starting DNSMasq config fixer for: {config_file}")
    success = fix_dnsmasq_config(config_file)
    sys.exit(0 if success else 1)