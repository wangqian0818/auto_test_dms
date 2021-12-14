# coding:utf-8
from common import baseinfo

mail_attach = baseinfo.mail_attach
proxy_ip = baseinfo.BG8010FrontOpeIp

action = 'allow'

'''
用例一：单个白名单，只包含发件人
        "RuleId":  104,
        "Action":  "Allow",
        "FromTo":  ["autotest_send@jusontech.com"]
'''

'''
用例二：多个白名单，白名单包含发件人和收件人
        "RuleId":  104,
        "Action":  "Allow",
        "FromTo":  ["autotest_send@jusontech.com", "autotest_recv@jusontech.com"]
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

title = '关于mail_check_addr'
context = '测试内容-content'
file = '1.xls'
attach_path = mail_attach + file

