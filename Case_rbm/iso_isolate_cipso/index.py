# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port

http_ip1 = proxy_ip + ':' + str(http_proxy_port)
http_url1 = 'http://' + http_ip1

http_content = baseinfo.http_content

cat = '0x1,0x2,0x3,0x4'
match = 1
doi = 16
clevel = 13

'''
用例一：验证隔离设备的带标记通信情况(A-B)
'''

case_curl = {
    "curl": [f"curl http://{proxy_ip}:{http_proxy_port} >/opt/pkt/acl_tcp.txt", 'cat /opt/pkt/acl_tcp.txt', http_content],
    "txt": ['acl_tcp.txt']
}

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
        f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {proxy_ip} ', f'doi {doi}'],
    "step2": [
        f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi {doi} --level {clevel} --biba --inc  --cat {cat}  -j CIPSO --rm', f'doi {doi}']
}

case1_step2 = {
    "step1": [
        f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {proxy_ip}', f'doi {doi}'],
    "step2": [
        f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi {doi} --level {clevel} --biba --inc  --cat {cat}  -j CIPSO --rm', f'doi {doi}']
}

'''
用例二：验证隔离设备的带标记通信情况(B-A)
'''

front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameInside

case2_gapFromTo = {
        "FromTo": "BA",  # 通信方向，AB与BA之间选一个；
        "Input": back_ifname,  # 入接口；非必选
        "Output": front_ifname  # 出接口；非必选
}
proxy2_ip = baseinfo.BG8010BackOpeIpInside
case2_curl = {
    "curl": [f"curl http://{proxy2_ip}:{http_proxy_port} >/opt/pkt/acl_tcp.txt", 'cat /opt/pkt/acl_tcp.txt', http_content],
    "txt": ['acl_tcp.txt']
}

case2_step1 = {
    "step1": [
        f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {proxy2_ip} ', f'doi {doi}'],
    "step2": [
        f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi {doi} --level {clevel} --biba --inc  --cat {cat}  -j CIPSO --rm', f'doi {doi}']
}

case2_step2 = {
    "step1": [
        f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {proxy2_ip}', f'doi {doi}'],
    "step2": [
        f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi {doi} --level {clevel} --biba --inc  --cat {cat}  -j CIPSO --rm', f'doi {doi}']
}


