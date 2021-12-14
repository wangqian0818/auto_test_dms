# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port

http_ip1 = proxy_ip + ':' + str(http_proxy_port)
http_url1 = 'http://' + http_ip1

front_ifname = baseinfo.BG8010FrontOpeIfname

sip = baseinfo.windows_sip
tcp = '6'
case1_content = {
    'RuleId': 8848,
    'Ifname': front_ifname,  # 具体接口，若策略不指定接口，则无此字段
    'Sip': sip,  # 源地址，支持添加掩码，例如：'10.10.100.0/24'
    'Sport': '0',  # 源端口，支持端口段，例如：'2000-3000'
    'Dip': proxy_ip,  # 目的地址，支持添加掩码，例如：'10.10.100.0/24'
    'Dport': f'{http_proxy_port}',  # 目的端口，支持端口段，例如：'2000-3000'
    'Protocol': tcp,  # 协议号，支持TCP，UDP和协议号数值
    'Listorder': 2,  # 优先级
    'Action': 1,  # 动作，0转发，1丢弃
    'Location': 'A',
}

back_ifname = baseinfo.BG8010BackOpeIfnameInside
back_ip = baseinfo.BG8010BackOpeIpInside
case2_content = {
    'RuleId': 8848,
    'Ifname': back_ifname,  # 具体接口，若策略不指定接口，则无此字段
    'Sip': sip,  # 源地址，支持添加掩码，例如：'10.10.100.0/24'
    'Sport': '0',  # 源端口，支持端口段，例如：'2000-3000'
    'Dip': back_ip,  # 目的地址，支持添加掩码，例如：'10.10.100.0/24'
    'Dport': f'{http_proxy_port}',  # 目的端口，支持端口段，例如：'2000-3000'
    'Protocol': tcp,  # 协议号，支持TCP，UDP和协议号数值
    'Listorder': 2,  # 优先级
    'Action': 1,  # 动作，0转发，1丢弃
    'Location': 'B',
}


