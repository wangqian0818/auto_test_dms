# coding:utf-8
from common import baseinfo

url = baseinfo.http_proxy_url
proxy_ip = baseinfo.gwClientIp
proxy_port = baseinfo.http_proxy_port

# 相关参数设置

'''
用例一： get,post请求，uri多条黑名单

"Action":  "Deny",
"Method":  ['GET', 'POST'],
"URI":  ['mzh', '456']
'''

method = ['GET', 'POST']
file_type = ["txt", "gif"]
uri = ['mzh', '456']

# /mzh
check_url1 = url + '/' + uri[0]
# /456
check_url2 = url + '/' + uri[1]
