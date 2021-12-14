# -*- coding: utf-8 -*-
import smtplib
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys, datetime, getopt


# 封装一个方法直接传入邮件标题和内容，发送邮件
def post_email(sender, receivers, mail_host, mail_port, mail_user, mail_pass,
               title, context):
    # 三个参数：第一个为文本内容，第二个 plain 设置文本格式，第三个 utf-8 设置编码
    msg = MIMEMultipart()
    msg['From'] = Header(sender)  # 发送者
    msg['To'] = Header(str(";".join(receivers)))  # 接收者,注意，不是分号
    msg['Subject'] = Header(title)  # 邮件主题
    context = str(context)  # 邮件内容
    txt = MIMEText(context, 'plain', 'utf-8')
    msg.attach(txt)

    try:
        smtpObj = smtplib.SMTP()
        smtpObj.connect(mail_host, mail_port)
        # smtpObj = smtplib.SMTP_SSL(mail_host, mail_port)      #qq邮箱的设置
        smtpObj.login(mail_user, mail_pass)
        smtpObj.sendmail(sender, receivers, msg.as_string())
        smtpObj.quit()  # 关闭邮箱连接
        return 1
    except smtplib.SMTPException:
        return 0

try:
    mail_user = "liuchao@jusontech.com"  # 邮件登录地址
    mail_pass = "1q2w3e"  # 授权码
    sender = 'liuchao@jusontech.com'  # 发件人
    receivers = ['liuchao@jusontech.com']  # 收件人
    mail_host = "192.168.50.33"  # 设置服务器,发件人的服务器代理
    mail_port = 25  # 设置服务器端口
    curtime = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    title = 'juson-test'
    context = 'juson-mail-test-context'
    opts, args = getopt.getopt(sys.argv[1:], "hu:c:r:i:p:t:n:", ["help"])
    for opts, arg in opts:
        if opts == "-h" or opts == "--help":
            print("-u mail_user")
            print("-c mail_pass")
            print("-r receiver")
            print("-i mail_host")
            print("-p mail_port")
            print("-t mail_title")
            print("-n mail_context")
        elif opts == "-u":
            mail_user = arg
            sender = mail_user
        elif opts == "-c":
            mail_pass = arg
        elif opts == "-r":
            receivers = [arg]
        elif opts == "-i":
            mail_host = arg
        elif opts == "-p":
            mail_port = int(arg)
        elif opts == "-t":
            title = arg
        elif opts == "-n":
            context = arg
    print(mail_user)
    print(receivers)
    print(mail_host)
    print(mail_port)
    print(title)
    print(context)
    # print(f'mail_user:{mail_user}')
    # print(f'receivers:{receivers}')
    # print(f'mail_host:{mail_host}')
    # print(f'mail_port:{mail_port}')
    # print(f'title:{title}')
    # print(f'context:{context}')
    result = post_email(sender, receivers, mail_host, mail_port, mail_user, mail_pass, title, context)


    print(result)
    if result == 1:
        print('send mail ok')
    else:
        print('send mail fail')
except Exception as err:
    print(err)
    sys.exit(0)
