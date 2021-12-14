# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
smtp_proxy_port = baseinfo.smtp_proxy_port
pop3_proxy_port = baseinfo.pop3_proxy_port
ftp_proxy_port = baseinfo.ftp_proxy_port
mail_attach = baseinfo.mail_attach
downremotePath = baseinfo.ftp_downremotePath
downlocalPath = baseinfo.ftp_downlocalPath
ftp_upremotePath = baseinfo.ftp_upremotePath
ftp_uplocalPath = baseinfo.ftp_uplocalPath

# smtp相关参数设置
mail_sender = 'autotest_send@jusontech.com'  # 发件人
mail_receivers = ['autotest_recv@jusontech.com', 'autotest_send@jusontech.com']  # 收件人
mail_cc = ['autotest_send@jusontech.com', 'autotest_recv@jusontech.com']  # 抄送人
mail_bcc = ['autotest_send@jusontech.com', 'autotest_recv@jusontech.com']  # 暗送人
mail_host = proxy_ip  # 设置服务器,发件人的服务器代理
mail_port = smtp_proxy_port  # 设置服务器端口
mail_user = "autotest_send@jusontech.com"  # 邮件登录地址
mail_pass = "lwq5945"  # 授权码
deny_mail = 'jusontest@163.com'
deny_pwd = 'UMXDELUQAPUWQFNU'

# pop3相关参数设置
# 获取邮箱密码和对应邮箱POP3服务器,邮件地址跟收件人相同
pop3_email = "autotest_recv@jusontech.com"
pop3_pwd = "DKIFMDALXMWLXCOW"
title = '关于iso_ftp_up_down'
context = '测试内容-content'
file = '50M.txt'
attach_path = mail_attach + file

# ftp相关参数设置
ftp_user = 'test'
ftp_pass = '1q2w3e'
case2_file = '100M.txt'
case2_downremotePath = downremotePath + case2_file
case2_downlocalPath = downlocalPath + case2_file
upremotePath = ftp_upremotePath + case2_file
uplocalPath = ftp_uplocalPath + case2_file
