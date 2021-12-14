# coding:utf-8
from common import baseinfo
import random

# 共用参数设置
sip = baseinfo.clientOpeIp
dip = baseinfo.serverOpeIp
udp_content = baseinfo.udp_content
dport = baseinfo.http_server_port
udp = '17'
gwOther1Ifname = baseinfo.gwOther1Ifname
action = [0, 1] # 动作，0转发，1丢弃

case_curl = {
    "curl": [f"python /opt/pkt/udp_client.py {dip} {dport} >/opt/pkt/acl_udp.txt", 'cat /opt/pkt/acl_udp.txt', udp_content],
    "txt": ['acl_udp.txt']
}
case_content = {
    'RuleId': 8848,
    'Ifname': gwOther1Ifname,  # 具体接口，若策略不指定接口，则无此字段
    'Sip': sip,  # 源地址，支持添加掩码，例如：'10.10.100.0/24'
    'Sport': '0',  # 源端口，支持端口段，例如：'2000-3000'
    'Dip': dip,  # 目的地址，支持添加掩码，例如：'10.10.100.0/24'
    'Dport': f'{dport}',  # 目的端口，支持端口段，例如：'2000-3000'
    'Protocol': udp,  # 协议号，支持TCP，UDP和协议号数值
    'Listorder': 2,  # 优先级
    'Action': action[1],  # 动作，0转发，1丢弃
}



