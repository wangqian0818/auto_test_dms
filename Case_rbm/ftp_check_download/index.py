# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.gwClientIp
downremotePath = baseinfo.ftp_downremotePath
downlocalPath = baseinfo.ftp_downlocalPath

# ftp相关参数设置
host = baseinfo.gwClientIp
port = baseinfo.ftp_proxy_port
username = baseinfo.ftp_user
password = baseinfo.ftp_pass
deny_user = 'lwq'

'''
用例一：单個download文件后缀名，黑名单
    'Action':'deny',
    'DownloadExt':['pdf']
'''

filename = '456.'
case1_downfile = 'txt'
case1_deny_downfile = 'pdf'
case1_file = filename + case1_downfile
case1_deny_file = filename + case1_deny_downfile
case1_downremotePath = downremotePath + case1_file
case1_downlocalPath = downlocalPath + case1_file
case1_deny_downremotePath = downremotePath + case1_deny_file
case1_deny_downlocalPath = downlocalPath + case1_deny_file

'''
用例二：多個download文件后缀名，黑名单
    'Action':'deny',
    'DownloadExt':['pdf','xls']
'''
check2_deny_download = ['pdf', 'xls']
check2_allow_download = 'txt'

case2_deny_file1 = filename + check2_deny_download[0]
case2_deny_file2 = filename + check2_deny_download[1]
case2_allow_file = filename + check2_allow_download
case2_deny_downremotePath1 = downremotePath + case2_deny_file1
case2_deny_downlocalPath1 = downlocalPath + case2_deny_file1
case2_deny_downremotePath2 = downremotePath + case2_deny_file2
case2_deny_downlocalPath2 = downlocalPath + case2_deny_file2
case2_allow_downremotePath = downremotePath + case2_allow_file
case2_allow_downlocalPath = downlocalPath + case2_allow_file
