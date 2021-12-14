# coding:utf-8
from common import baseinfo
import random

# 共用参数设置
cipso_sip = baseinfo.clientOpeIp
cipso_dip = baseinfo.serverOpeIp
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface
strip = baseinfo.strip

dport = baseinfo.http_server_port
cat = '0x1,0x2,0x3,0x4'
match = 1
doi = 16
clevel = 13
http_content = baseinfo.http_content
cipso_doi = {
    "curl": [f"curl http://{cipso_dip}:{dport} >/opt/cipso_curl_doi.txt", 'cat /opt/cipso_curl_doi.txt', http_content],
    "txt": ['cipso_curl_doi.txt']
}

'''
用例一：验证标记对tcp报文的完整通信
'''
case1_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': 1,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '13-13',  # 机密性级别比较范围
        'Integrity': '',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}
case1_step1 = {
    "step1": [
        f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {cipso_dip} ', f'doi {doi}'],
    "step2": [
        f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi {doi} --level {clevel} --biba --inc  --cat {cat} -s {cipso_sip} -j CIPSO --rm', f'doi {doi}']
}

case1_step2 = {
    "step1": [
        f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {cipso_dip}', f'doi {doi}'],
    "step2": [
        f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi {doi} --level {clevel} --biba --inc  --cat {cat} -s {cipso_sip} -j CIPSO --rm', f'doi {doi}']
}

