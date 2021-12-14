# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
ftp_proxy_port = baseinfo.ftp_proxy_port
downremotePath = baseinfo.ftp_downremotePath
downlocalPath = baseinfo.ftp_downlocalPath
ftp_upremotePath = baseinfo.ftp_upremotePath
ftp_uplocalPath = baseinfo.ftp_uplocalPath

# ftp相关参数设置
ftp_user = baseinfo.ftp_user
ftp_pass = baseinfo.ftp_pass
case2_file = '100M.txt'
# case2_file = '10G.txt'
case2_downremotePath = downremotePath + case2_file
case2_downlocalPath = downlocalPath + case2_file
upremotePath = ftp_upremotePath + case2_file
uplocalPath = ftp_uplocalPath + case2_file

ftp_ip = proxy_ip + ':' + str(ftp_proxy_port)
