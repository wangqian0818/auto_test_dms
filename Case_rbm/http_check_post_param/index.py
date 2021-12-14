# coding:utf-8
from common import baseinfo

url = baseinfo.http_proxy_url
proxy_ip = baseinfo.gwClientIp
proxy_port = baseinfo.http_proxy_port

check_url = url + '/1.txt'

'''
用例一：

"Action":  "Deny",
"Method":  ['POST'],
"Parameter":  ["name"]
'''

method = ['POST']
case1_parameter = ["name"]

# ?name=wq
check1_url1 = url + '?' + case1_parameter[0] + '=wq'

'''
用例二：

"Action":  "Deny",
"Method":  ['POST'],
"Parameter":  ["name","age"]
'''

case2_parameter = ["name", "age"]

# name=wq
check2_url1 = url + '?' + case2_parameter[0] + '=wq'
# /age=18
check2_url2 = url + '?' + case2_parameter[1] + '=18'
