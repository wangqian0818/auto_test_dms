# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port
http_server_port_file = baseinfo.http_server_port_file

remote_downfile = '100M.txt'

http_ip = proxy_ip + ':' + str(http_proxy_port)
http_file_ip = proxy_ip + ':' + str(http_server_port_file)
http_url = 'http://' + proxy_ip + ':' + str(http_proxy_port)
downfile_url = 'http://' + proxy_ip + ':' + str(http_proxy_port) + '/' + remote_downfile
downlocalPath = baseinfo.http_downlocalPath + remote_downfile
up_url = 'http://' + proxy_ip + ':' + str(http_server_port_file)
upfile_url = up_url + '/file'
# upfilename = '10G.txt'
upfilename = '100M.txt'
uplocalPath = baseinfo.http_uplocalPath + upfilename
upMIME_type = 'text/plain'
