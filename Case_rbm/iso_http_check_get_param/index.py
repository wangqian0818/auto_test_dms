# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
proxy_port = baseinfo.http_proxy_port
url = 'http://' + proxy_ip + ':' + str(proxy_port)

# 对照黑名单的url
case_data = url + '/' + '1.txt'
"""
用例一：parameter 单个黑名单
"Action":  "deny"
"Parameter":  ["name"]
"""
# http parameter黑名单相关参数设置,隔离parameter设计是针对？后面的key,全匹配比如?name=wq，parameter就是name
check1_data = 'name'
case1_data = url + '?' + check1_data + '=wq'

"""
用例二：parameter  多个黑名单
"Action":  "deny"
"Parameter":  ['name', 'age']
"""
check2_data = ['name', 'age']
case2_data1 = url + '?' + check2_data[0] + '=wq'
case2_data2 = url + '?' + check2_data[1] + '=18'
