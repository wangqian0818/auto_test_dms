# coding:utf-8
from common import baseinfo
import random

# 共用参数设置
sip = baseinfo.clientOpeIp
dip = baseinfo.serverOpeIp
udp_content = baseinfo.udp_content
http_content = baseinfo.http_content
dport = baseinfo.http_server_port

mail_sender = baseinfo.mail_sender
mail_pass = baseinfo.mail_pass
mail_receiver = baseinfo.mail_receivers[0]
smtp_ip = baseinfo.smtp_ip
smtp_server_port = baseinfo.smtp_server_port
pop3_ip = baseinfo.pop3_ip
pop3_server_port = baseinfo.pop3_server_port
case1_curl = {
    "curl": [f"curl http://{dip}:{dport} >/opt/pkt/route_tcp.txt", 'cat /opt/pkt/route_tcp.txt', http_content],
    "txt": ['route_tcp.txt']
}


case2_curl = {
    "curl": [f"python /opt/pkt/udp_client.py {dip} {dport} >/opt/pkt/route_udp.txt", 'cat /opt/pkt/route_udp.txt', udp_content],
    "txt": ['route_udp.txt']
}


titlenum = random.randint(1111, 99999)

case3_smtp = {
    "curl": [f"python /opt/pkt/mail_send_smtp.py -u {mail_sender} -r {mail_receiver} -i {smtp_ip} -p {smtp_server_port}"
             f" -t juson-test{titlenum} >/opt/pkt/mail_smtp.txt", 'cat /opt/pkt/mail_smtp.txt', 'send mail ok'],
    "txt": ['mail_smtp.txt']
}
case3_pop3 = {
    "curl": [f"python /opt/pkt/mail_recv_pop3.py -u {mail_sender} -c {mail_pass} -i {pop3_ip} -p {pop3_server_port} >"
             f"/opt/pkt/mail_pop3.txt", 'cat /opt/pkt/mail_pop3.txt', f'juson-test{titlenum}'],
    "txt": ['mail_pop3.txt']
}
