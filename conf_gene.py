#!/usr/bin/env python3
"""
DNSMASQ 配置文件批量生成器
生成64个高度差异化的配置文件，覆盖所有核心功能模块
"""

import os
import random
import jinja2
from jinja2 import Template

# ----------------- 配置常量 -----------------
CONFIG_COUNT = 64                # 生成配置文件数量
OUTPUT_DIR = "conf"           # 输出目录
TEMPLATE_FILE = "template.j2"    # Jinja2模板文件
MAC_PREFIX = "02:00:00:%02x:%02x:%02x"  # MAC地址生成格式

# ----------------- 模板内容 -----------------
TEMPLATE_CONTENT = """{# 基于官方文档的全功能模板 #}
# =============== dnsmasq-{{ id }}.conf ===============
# 生成ID: {{ id }}
# 端口: {{ port }}
# 子网: {{ subnet }}

{# 基础设置 #}
port={{ port }}
bind-interfaces
listen-address={{ listen_ip }}
no-hosts
expand-hosts
domain={{ domain }}

{# DNS配置 #}
{% if dns_mode == "strict" %}strict-order{% elif dns_mode == "noresolv" %}no-resolv{% endif %}
{% for server in dns_servers %}
server={{ server }}{% endfor %}
bogus-nxdomain={{ bogus_ip }}
address=/{{ force_domain }}/{{ force_ip }}

{# DHCP配置 #}
dhcp-range={{ dhcp_range }}
dhcp-option=option:router,{{ gateway }}
dhcp-option=option:ntp-server,{{ ntp_server }}
{% for host in static_hosts %}
dhcp-host={{ host.mac }},{{ host.ip }},{{ host.name }}{% endfor %}

{# 安全配置 #}
{% if security_level > 0 %}filterwin2k
bogus-priv{% endif %}
{% if security_level > 1 %}no-poll
dhcp-ignore=tag:!known{% endif %}

{# 高级功能 #}
{% if enable_tftp %}enable-tftp
tftp-root={{ tftp_root }}{% endif %}
{% if enable_dnssec %}dnssec
conf-file={{ dnssec_path }}{% endif %}

{# 日志配置 #}
log-queries
log-dhcp
log-facility={{ log_path }}
log-async=20
"""

# ----------------- 工具函数 -----------------
def generate_mac(id):
    """生成唯一的MAC地址"""
    return MAC_PREFIX % ((id*3)%256, (id*5)%256, (id*7)%256)

def generate_static_hosts(id, count=3):
    """生成静态主机配置"""
    return [{
        "mac": generate_mac(id*10+i),
        "ip": f"192.168.{id}.{150+i}",
        "name": f"device-{id}-{i}"
    } for i in range(count)]

# ----------------- 主逻辑 -----------------
def main():
    # 初始化环境
    env = jinja2.Environment(loader=jinja2.BaseLoader())
    template = env.from_string(TEMPLATE_CONTENT)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 生成64个配置
    for config_id in range(CONFIG_COUNT):
        # 动态参数计算
        params = {
            "id": config_id,
            "port": 5353 + config_id,
            "subnet": f".168192.{config_id}.0/24",
            "listen_ip": f"127.0.0.1",
            "domain": f"test{config_id}.local",
            
            # DNS配置
            "dns_mode": random.choice(["strict", "noresolv", ""]),
            "dns_servers": random.sample(["8.8.8.8", "1.1.1.1", "9.9.9.9"], 2),
            "bogus_ip": "64.94.110.11" if config_id % 4 == 0 else "0.0.0.0",
            "force_domain": f"api{config_id}.test",
            "force_ip": f"192.168.{config_id}.100",
            
            # DHCP配置
            "dhcp_range": f"192.168.{config_id}.100,192.168.{config_id}.200,255.255.255.0,{random.choice(['6h','12h','24h'])}",
            "gateway": f"192.168.{config_id}.1",
            "ntp_server": f"192.168.{config_id}.1" if config_id % 3 == 0 else "pool.ntp.org",
            "static_hosts": generate_static_hosts(config_id),
            
            # 安全配置
            "security_level": config_id % 3,
            
            # 高级功能
            "enable_tftp": config_id % 5 == 0,
            "enable_dnssec": config_id % 7 == 0,
            "dnssec_path": f"/etc/dnsmasq/dnssec-{config_id}.conf",
            
            # 日志配置
            "log_path": f"/var/log/dnsmasq-{config_id}.log"
        }

        # 渲染配置
        output = template.render(**params)
        
        # 写入文件
        filename = os.path.join(OUTPUT_DIR, f"dnsmasq-{config_id:02d}.conf")
        with open(filename, "w") as f:
            f.write(output)
            

    print(f"成功生成 {CONFIG_COUNT} 个配置文件到 {OUTPUT_DIR} 目录")

if __name__ == "__main__":
    main()
