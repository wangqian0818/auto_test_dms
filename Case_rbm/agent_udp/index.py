# coding:utf-8
from common import baseinfo

url = baseinfo.http_proxy_url
# 反向代理使用
proxy_ip = baseinfo.gwClientIp
proxy_port = baseinfo.http_proxy_port
udp_content = baseinfo.udp_content

# 透明代理
server_id = baseinfo.http_server_ip
server_port = baseinfo.http_server_port

# 反向代理请求
curl1 = {
    "curl": [f"python /opt/pkt/udp_client.py {proxy_ip} {proxy_port} >/opt/pkt/agent_udp1.txt", 'cat /opt/pkt/agent_udp1.txt', udp_content],
    "txt": ['agent_udp1.txt']
}
# 透明代理请求
curl2 = {
    "curl": [f"python /opt/pkt/udp_client.py {server_id} {server_port} >/opt/pkt/agent_udp2.txt", 'cat /opt/pkt/agent_udp2.txt', udp_content],
    "txt": ['agent_udp2.txt']
}

