# -*- coding: utf-8 -*-
import logging
import smtplib
from email.header import Header
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from common import baseinfo

log = logging.getLogger(__name__)

mail_sender = baseinfo.mail_sender  # 发件人
mail_receivers = baseinfo.mail_receivers  # 收件人
mail_cc = baseinfo.mail_cc  # 抄送人
mail_bcc = baseinfo.mail_bcc  # 暗送人
mail_port1 = baseinfo.smtp_proxy_port  # 设置服务器端口
mail_user1 = baseinfo.mail_user  # 邮件登录地址
mail_pass1 = baseinfo.mail_pass  # 授权码
mail_attach = baseinfo.mail_attach
title1 = '公共方法send_smtp.post_email()的默认title'
context1 = '公共方法send_smtp.post_email()的默认content'
file1 = '1.xls'
attach_path1 = mail_attach + file1


# 封装一个方法直接传入邮件标题和内容，发送邮件
def post_email(sender, receivers, cc_list, bcc_list, mail_host, mail_port, mail_user, mail_pass, attach_path, file,
               title, context, cc_flag=0, part_flag=0):
    if sender == '':
        sender = mail_sender
    if receivers == '':
        receivers = mail_receivers
    if cc_list == '':
        cc_list = []
    if bcc_list == '':
        bcc_list = []
    if mail_port == '':
        mail_port = mail_port1
    if mail_user == '':
        mail_user = mail_user1
    if mail_pass == '':
        mail_pass = mail_pass1
    if attach_path == '':
        attach_path = attach_path1
    if file == '':
        file = file1
    if title == '':
        title = title1
    if context == '':
        context = context1

    log.warning('sender：{}\nreceivers：{}\ncc_list：{}\nbcc_list：{}\nmail_host：{}\nmail_port：{}'
                '\nmail_user：{}\nmail_pass：{}\nattach_path：{}\nfile：{}\ntitle：{}\ncontext：{}'
                '\ncc_flag：{}\npart_flag：{}\n'.format(sender, receivers, cc_list, bcc_list, mail_host, mail_port,
                                                      mail_user, mail_pass, attach_path, file, title, context, cc_flag,
                                                      part_flag))

    # 三个参数：第一个为文本内容，第二个 plain 设置文本格式，第三个 utf-8 设置编码
    msg = MIMEMultipart()
    msg['From'] = Header(sender)  # 发送者
    msg['To'] = Header(str(";".join(receivers)))  # 接收者,注意，不是分号
    msg['Cc'] = ','.join(cc_list)  # 抄送者
    msg['Bcc'] = ','.join(bcc_list)  # 暗送者
    msg['Subject'] = Header(title)  # 邮件主题
    context = str(context)  # 邮件内容
    txt = MIMEText(context, 'plain', 'utf-8')
    msg.attach(txt)
    if part_flag == 1:
        log.warning("准备添加附件...")
        if isinstance(attach_path, str):
            # 添加附件，从本地路径读取。如果添加多个附件，可以定义part_2,part_3等，然后使用part_2.add_header()和msg.attach(part_2)即可。
            part = MIMEApplication(open(attach_path, 'rb').read())
            part.add_header('Content-Disposition', 'attachment', filename=file)  # 给附件重命名,一般和原文件名一样,改错了可能无法打开.
            msg.attach(part)
        elif isinstance(attach_path, list):
            for i in range(len(attach_path)):
                part = MIMEApplication(open(attach_path[i], 'rb').read())
                part.add_header('Content-Disposition', 'attachment', filename=file[i])  # 给附件重命名,一般和原文件名一样,改错了可能无法打开.
                msg.attach(part)
    try:
        smtpObj = smtplib.SMTP()
        smtpObj.connect(mail_host, mail_port)
        # smtpObj = smtplib.SMTP_SSL(mail_host, mail_port)      #qq邮箱的设置
        smtpObj.login(mail_user, mail_pass)
        if cc_flag == 0:
            smtpObj.sendmail(sender, receivers, msg.as_string())
        elif cc_flag == 1:
            smtpObj.sendmail(sender, receivers + cc_list + bcc_list, msg.as_string())
        smtpObj.quit()  # 关闭邮箱连接
        return 1
    except smtplib.SMTPException:
        return 0


#
if __name__ == '__main__':
    sender = 'autotest_send@jusontech.com'  # 发件人
    receivers = ['autotest_recv@jusontech.com']  # 收件人

    # cc_list = ['autotest_send2@jusontech.com', 'autotest_recv2@jusontech.com']  # 抄送人
    # bcc_list = ['autotest_send2@jusontech.com', 'autotest_recv2@jusontech.com']  # 暗送人
    cc_list = []  # 抄送人
    bcc_list = []  # 暗送人

    mail_host = "10.10.101.33"  # 设置服务器,发件人的服务器代理
    mail_port = 25  # 设置服务器端口
    # mail_host = "192.168.30.47"  # 设置服务器,发件人的服务器代理
    # mail_port = 8885  # 设置服务器端口

    mail_user = "autotest_send@jusontech.com"  # 邮件登录地址
    mail_pass = "1q2w3e"  # 授权码
    # attach_path = r'C:\Users\admin\Desktop\work\1.xls'  # 本地附件路径   卓讯  5Y2T6K6v
    # file = '1.xls'
    attach_path = [r'C:\Users\admin\Desktop\work\1.xls', r'C:\Users\admin\Desktop\work\1.txt']  # 本地附件路径   卓讯  5Y2T6K6v
    file = ['1.xls', '1.txt']
    # title = '测试邮件关键字过滤——juson'  # juson   anVzb24=
    # context = '测试邮件关键字过滤——tech'  # tech    dGVjaA==
    title = '公共方法send_smtp.post_email()的默认title'
    context = '读表执行用例的content'
    result = post_email(sender, receivers, cc_list, bcc_list, mail_host, mail_port, mail_user, mail_pass, attach_path,
                        file, title, context, 0, 1)
    log.warning(result)
    if result == 1:
        log.warning('成功')
    else:
        log.warning('失败')
