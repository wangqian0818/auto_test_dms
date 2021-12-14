# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
mail_attach = baseinfo.mail_attach

'''
用例：收件人发件人白名单+主体、附件后缀名黑名单
        "RuleId":  103,
        "Action":  "Allow",
        "FromTo":  ["autotest_send@jusontech.com", "autotest_recv@jusontech.com"]
      }, {
        "RuleId":  104,
        "Action":  "Deny",
        "Subject":  ["test"],
        "AttachmentExt":  ["txt"]
'''

# smtp相关参数设置
mail_sender = baseinfo.mail_sender  # 发件人
mail_receivers = baseinfo.mail_receivers  # 收件人
mail_cc = baseinfo.mail_cc  # 抄送人
mail_bcc = baseinfo.mail_bcc  # 暗送人
mail_host = proxy_ip  # 设置服务器,发件人的服务器代理
mail_port = baseinfo.smtp_proxy_port  # 设置服务器端口
mail_user = baseinfo.mail_user  # 邮件登录地址
mail_pass = baseinfo.mail_pass  # 授权码
deny_mail = 'jusontest@163.com'
deny_pwd = 'UMXDELUQAPUWQFNU'

# pop3相关参数设置
# 获取邮箱密码和对应邮箱POP3服务器,邮件地址跟收件人相同
pop3_email = baseinfo.pop3_email
pop3_pwd = baseinfo.pop3_pwd  # 授权码
pop3_proxy_host = proxy_ip
pop3_proxy_port = baseinfo.pop3_proxy_port

deny_title = 'test'
title = '我不是黑名单主题，测试多种类型'
deny_filename = 'test'
deny_extend = 'txt'
filename = '1'
extend = 'xls'
deny_name_file = deny_filename + '.' + extend
deny_extend_file = filename + '.' + deny_extend
file = filename + '.' + extend
attach_file = mail_attach + deny_name_file
attach_extend = mail_attach + deny_extend_file
attach_path = mail_attach + file
context = 'mail_check_alltype____测试内容'
