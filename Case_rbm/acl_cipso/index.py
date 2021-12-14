# coding:utf-8
from common import baseinfo
import random

# 共用参数设置
sip = baseinfo.clientOpeIp
dip = baseinfo.serverOpeIp
http_content = baseinfo.http_content
dport = baseinfo.http_server_port
tcp = '6'
gwOther1Ifname = baseinfo.gwOther1Ifname
action = [0, 1] # 动作，0转发，1丢弃

case_curl = {
    "curl": [f"curl http://{dip}:{dport} >/opt/pkt/acl_tcp.txt", 'cat /opt/pkt/acl_tcp.txt', http_content],
    "txt": ['acl_tcp.txt']
}
'''
用例一：验证网络安全策略协议为TCP、动作执行为允许的情况（设备下发标记）
'''
case1_content = {
    'RuleId': 8848,
    'Ifname': gwOther1Ifname,  # 具体接口，若策略不指定接口，则无此字段
    'Sip': sip,  # 源地址，支持添加掩码，例如：'10.10.100.0/24'
    'Sport': '0',  # 源端口，支持端口段，例如：'2000-3000'
    'Dip': dip,  # 目的地址，支持添加掩码，例如：'10.10.100.0/24'
    'Dport': f'{dport}',  # 目的端口，支持端口段，例如：'2000-3000'
    'Protocol': tcp,  # 协议号，支持TCP，UDP和协议号数值
    'Listorder': 2,  # 优先级
    'Action': action[0],  # 动作，0转发，1丢弃
}

cat = '0x1,0x2,0x3,0x4'
match = 1
doi = 16
clevel = 13

case1_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': 1,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '13-13',  # 机密性级别比较范围
        'Integrity': '',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}


case1_step1 = {
    "step1": [
        f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {dip} ', f'doi {doi}'],
    "step2": [
        f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi {doi} --level {clevel} --biba --inc  --cat {cat} -s {sip} -j CIPSO --rm', f'doi {doi}']
}

case1_step2 = {
    "step1": [
        f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {dip}', f'doi {doi}'],
    "step2": [
        f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi {doi} --level {clevel} --biba --inc  --cat {cat} -s {sip}  -j CIPSO --rm', f'doi {doi}']
}

