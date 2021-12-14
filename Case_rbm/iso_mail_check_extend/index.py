# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
mail_attach = baseinfo.mail_attach


'''
用例一：单个黑名单，附件后缀名
        "RuleId": 104,
        "Action": "Deny",
        "AttachmentExt": ["txt"]

'''

'''
用例二：多个黑名单，附件后缀名
        "RuleId":  104,
        "Action":  "Deny",
        "AttachmentExt":  ["txt", "pdf"]
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
file = '1.'
case1_title = '测试黑名单附件扩展名'
case1_extend1 = 'txt'
case1_extend2 = 'xls'
case1_file1 = file + case1_extend1
case1_file2 = file + case1_extend2
case1_attach1 = mail_attach + case1_file1
case1_attach2 = mail_attach + case1_file2

case2_title = '测试黑名单附件扩展名!!'
case2_extend1 = 'txt'
case2_extend2 = 'pdf'
case2_extend3 = 'xls'
case2_file1 = file + case2_extend1
case2_file2 = file + case2_extend2
case2_file3 = file + case2_extend3
case2_attach1 = mail_attach + case2_file1
case2_attach2 = mail_attach + case2_file2
case2_attach3 = mail_attach + case2_file3