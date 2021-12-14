# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.gwClientIp
mail_attach = baseinfo.mail_attach



'''
用例一：Subject单个黑名单
        "RuleId": 104,
        "Action": "Deny",
        "Subject": ["test"]
'''

'''
用例二：Subject多个黑名单
        "RuleId": 104,
        "Action": "Deny",
        "Subject": ["test", "abc"]
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

context = '测试测试测试'
file = '1.xls'
attach_path = mail_attach + file
case1_title1 = 'test'
case1_title2 = '我不是黑名单主题'
case2_title1 = 'test'
case2_title2 = 'abc'
case2_title3 = '我不是黑名单主题!!'
