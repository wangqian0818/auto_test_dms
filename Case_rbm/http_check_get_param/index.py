# coding:utf-8
from common import baseinfo

url = baseinfo.http_proxy_url
proxy_ip = baseinfo.gwClientIp
proxy_port = baseinfo.http_proxy_port

# 对照黑名单的url
case_data = url + '/' + '1.txt'
"""
用例一：parameter 单个黑名单
"Action":  "deny"
"Parameter":  ["pcap"]
"""
# http parameter黑名单相关参数设置,目前parameter设计只针对文件后缀名进行判断
check1_data = 'pcap'
case1_data = url + '/' + 'test.' + check1_data

"""
用例二：parameter  多个黑名单
"Action":  "deny"
"Parameter":  ['pdf', 'js']
"""
check2_data = ['pdf', 'js']
case2_data1 = url + '/' + 'test.' + check2_data[0]
case2_data2 = url + '/' + 'test.' + check2_data[1]
