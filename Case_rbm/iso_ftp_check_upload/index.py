# coding:utf-8
from common import baseinfo

upremotePath = baseinfo.ftp_upremotePath
uplocalPath = baseinfo.ftp_uplocalPath
downremotePath = baseinfo.ftp_downremotePath
downlocalPath = baseinfo.ftp_downlocalPath

# ftp相关参数设置
host = baseinfo.BG8010FrontOpeIp
port = baseinfo.ftp_proxy_port
username = baseinfo.ftp_user
password = baseinfo.ftp_pass
deny_user = 'lwq'
action = 'deny'

'''
用例一：单個upload文件后缀名，黑名单
    'Action':'deny',
    'UploadExt':['txt']
'''
cmd_upload = 'STOR'
filename = '1.'
case1_upload = 'txt'
case1_deny_upload = 'pdf'
case1_file = filename + case1_upload
case1_deny_file = filename + case1_deny_upload
case1_upremotePath = upremotePath + case1_file
case1_uplocalPath = uplocalPath + case1_file
case1_deny_upremotePath = upremotePath + case1_deny_file
case1_deny_uplocalPath = uplocalPath + case1_deny_file

'''
用例二：多個upload文件后缀名，黑名单
    'Action':'deny',
    'UploadExt':['txt','xls']
'''
check2_deny_upload = ['txt', 'xls']
check2_allow_upload = 'pdf'
case2_deny_file1 = filename + check2_deny_upload[0]
case2_deny_file2 = filename + check2_deny_upload[1]
case2_allow_file = filename + check2_allow_upload

case2_deny_upremotePath1 = upremotePath + case2_deny_file1
case2_deny_uplocalPath1 = uplocalPath + case2_deny_file1
case2_deny_upremotePath2 = upremotePath + case2_deny_file2
case2_deny_uplocalPath2 = uplocalPath + case2_deny_file2
case2_allow_upremotePath = upremotePath + case2_allow_file
case2_allow_uplocalPath = uplocalPath + case2_allow_file
