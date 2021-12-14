# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port

http_ip1 = proxy_ip + ':' + str(http_proxy_port)
http_ip2 = proxy_ip + ':' + str(http_proxy_port+1)
http_url1 = 'http://' + http_ip1
http_url2 = 'http://' + http_ip2
udp_content = baseinfo.udp_content

udp_url1 = {
    "curl": [f"python /opt/pkt/udp_client.py {proxy_ip} {http_proxy_port} >/opt/pkt/iso_udp1.txt", 'cat /opt/pkt/iso_udp1.txt', udp_content],
    "txt": ['iso_udp1.txt']
}
udp_url2 = {
    "curl": [f"python /opt/pkt/udp_client.py {proxy_ip} {http_proxy_port+1} >/opt/pkt/iso_udp2.txt", 'cat /opt/pkt/iso_udp2.txt', udp_content],
    "txt": ['iso_udp2.txt']
}


ftp2_ip = '10.10.101.4'
ftp2_dport = 21
ftp2_user = 'test'
ftp2_pass = '1q2w3e'


