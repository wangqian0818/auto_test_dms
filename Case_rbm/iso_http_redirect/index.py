# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port

http_ip = proxy_ip + ':' + str(http_proxy_port)
http_url = 'http://' + proxy_ip + ':' + str(http_proxy_port)
