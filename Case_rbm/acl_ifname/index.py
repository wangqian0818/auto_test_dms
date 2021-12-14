# coding:utf-8
from common import baseinfo
import random

# 共用参数设置
sip = baseinfo.clientOpeIp
dip = baseinfo.serverOpeIp
http_content = baseinfo.http_content
dport = baseinfo.http_server_port
tcp = '6'
udp = '17'
bond1 = baseinfo.DeviceObject['gateway', 'vlanIfname2']
action = [0, 1] # 动作，0转发，1丢弃
'''
用例一：验证网络安全策略下发Bond接口动作执行为阻止的情况
'''

case1_content = {
    'RuleId': 8848,
    'Ifname': bond1,  # 具体接口，若策略不指定接口，则无此字段
    'Sip': sip,  # 源地址，支持添加掩码，例如：'10.10.100.0/24'
    'Sport': '0',  # 源端口，支持端口段，例如：'2000-3000'
    'Dip': dip,  # 目的地址，支持添加掩码，例如：'10.10.100.0/24'
    'Dport': f'{dport}',  # 目的端口，支持端口段，例如：'2000-3000'
    'Protocol': tcp,  # 协议号，支持TCP，UDP和协议号数值
    'Listorder': 2,  # 优先级
    'Action': action[0],  # 动作，0转发，1丢弃
}

case1_curl = {
    "curl": [f"curl http://{dip}:{dport} >/opt/pkt/acl_tcp.txt", 'cat /opt/pkt/acl_tcp.txt', http_content],
    "txt": ['acl_tcp.txt']
}


