# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.gwClientIp

# ftp相关参数设置


action = 'allow'
host = baseinfo.gwClientIp
port = baseinfo.ftp_proxy_port
username = baseinfo.ftp_user
password = baseinfo.ftp_pass
deny_user = 'lwq'

"""
用例一：user 单个白名单
"Action":  "allow"
"User":  ["test"]
"""
case1_deny_user = 'lwq'

"""
用例二：user 多个白名单
"Action":  "allow"
"User":  ["test",'lwq']
"""
data2_check = ['test', 'lwq']
case2_deny_user = 'cpz'
case2_allow_user = 'lwq'
