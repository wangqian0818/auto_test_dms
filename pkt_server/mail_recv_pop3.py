# -*- coding: utf-8 -*-
#import logging
import poplib
from email.header import decode_header
from email.parser import Parser
from email.utils import parseaddr
import getopt, sys

#log = logging.getLogger(__name__)

def get_email(email, password, pop3_proxy_host, pop3_proxy_port):
    try:
        # 链接到POP3服务器
        server = poplib.POP3(pop3_proxy_host, pop3_proxy_port)
        # 打开调试，打印出会话内容，可选
        server.set_debuglevel(1)
        # 打印POP3服务器的欢迎文字，可选
        # log.warning(server.getwelcome().decode('utf-8'))

        # 进行身份认证
        server.user(email)
        server.pass_(password)

        # stat() 返回邮件数量和占用空间，返回两个。
        messages, size = server.stat()
        # log.warning('Messages: %s. Size: %s' %(messages, size))

        # list 返回所有邮件编号，第一个是返回状态信息，第二个是列表
        resp, mails, octets = server.list()
        # log.warning("邮件列表",mails)

        # 获取最新一封邮件, 注意索引号从1开始,最后是最新的
        index = len(mails)
        resp, lines, octets = server.retr(index)

        # lines存储了邮件的原始文本的每一行,
        # 可以获得整个邮件的原始文本:
        msg_content = b'\r\n'.join(lines).decode('utf-8')
        # 解析成massage对象,但是这个 Message 对象本身可能是一个 MIMEMultipart 对象，即包含嵌套的其他 MIMEBase 对象，嵌套可能还不止一层。所以要递归地打印出 Message 对象的层次结构
        msg = Parser().parsestr(msg_content)
        # log.warning(type(msg))    # <class 'email.message.Message'>
        # log.warning(msg)

        # 可以根据邮件索引号直接从服务器删除邮件:
        # server.dele(index)
        # 关闭连接
        server.quit()
        return msg
    except Exception:
        return 0

    # # 解析邮件正文


def decode_str(s):
    value, charset = decode_header(s)[0]
    if charset:
        value = value.decode(charset)
    return value


def guess_charset(msg):
    charset = msg.get_charset()
    if charset is None:
        content_type = msg.get('Content-Type', '').lower()
        pos = content_type.find('charset=')
        if pos >= 0:
            charset = content_type[pos + 8:].strip()
    return charset


mail_list = []


def print_info(msg, indent=0):
    global mail_list
    if indent == 0:
        for header in ['From', 'To', 'Cc', 'Subject']:
            value = msg.get(header, '')
            if value:
                if header == 'Subject':
                    value = decode_str(value)
                else:
                    hdr, addr = parseaddr(value)
                    name = decode_str(hdr)
                    value = u'%s <%s>' % (name, addr)
            mail_list.append(value)
    if (msg.is_multipart()):
        parts = msg.get_payload()
        for n, part in enumerate(parts):
            print_info(part, indent + 1)
    else:
        content_type = msg.get_content_type()
        if content_type == 'text/plain' or content_type == 'text/html':
            content = msg.get_payload(decode=True)
            charset = guess_charset(msg)
            if charset:
                content = content.decode(charset)
            mail_list.append(content)
        else:
            mail_list.append(content_type)
    return mail_list

try:
    mail_user = "liuchao@jusontech.com"
    mail_pass = "1q2w3e"
    pop3_host = "10.10.101.33"
    pop3_port = 110
    opts, args = getopt.getopt(sys.argv[1:], "hu:c:i:p:", ["help"])
    for opts, arg in opts:
        if opts == "-h" or opts == "--help":
            print("-u mail_user")
            print("-c mail_pass")
            print("-i pop3_host")
            print("-p pop3_port")
        elif opts == "-u":
            mail_user = arg
            sender = mail_user
        elif opts == "-c":
            mail_pass = arg
        elif opts == "-i":
            pop3_host = arg
        elif opts == "-p":
            pop3_port = int(arg)
    msg = get_email(mail_user, mail_pass, pop3_host, pop3_port)
    mail_list = print_info(msg)  # 解析
    print(mail_list)
except Exception as err:
    print(err)
    sys.exit(0)
