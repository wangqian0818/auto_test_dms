# coding:utf-8
from common import baseinfo

url = baseinfo.http_proxy_url
# 反向代理使用
proxy_ip = baseinfo.gwClientIp
proxy_port = baseinfo.http_proxy_port
proxy_http_content = baseinfo.http_content

# 透明代理
server_id = baseinfo.http_server_ip
server_port = baseinfo.http_server_port
http_content = baseinfo.http_content

cat = '0x1,0x2,0x3,0x4'
doi = 16
clevel = 13

# 反向代理请求
curl1 = {
    "curl": [f"curl http://{proxy_ip}:{proxy_port} >/opt/agent_tcp1.txt", 'cat /opt/agent_tcp1.txt', proxy_http_content],
    "txt": ['agent_tcp1.txt']
}
# 透明代理请求
curl2 = {
    "curl": [f"curl http://{server_id}:{server_port} >/opt/agent_tcp2.txt", 'cat /opt/agent_tcp2.txt', http_content],
    "txt": ['agent_tcp2.txt']
}

'''
用例三：验证网关设备下加标记的tcp协议反向代理策略（双向通信）
'''
case3_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': 1,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '13-13',  # 机密性级别比较范围
        'Integrity': '',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}
case3_step1 = {
    "step1": [
        f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {proxy_ip} ', f'cat {cat}'
    # "step2": [
    #     f'iptables -I PREROUTING -t mangle -p tcp  -j CIPSO --rm', '--rm'
    ]
}

case3_step2 = {
    "step1": [
        f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {proxy_ip}', f'cat {cat}'
        # f'iptables -D PREROUTING -t mangle -p tcp  -j CIPSO --rm', '--rm'
    ]
}


'''
用例四：验证网关设备下加标记的tcp协议透明代理策略（双向通信）
'''
case4_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': 1,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '13-13',  # 机密性级别比较范围
        'Integrity': '',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}
case4_step1 = {
    "step1": [
        f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {server_id} ', f'cat {cat}'
    ]
}

case4_step2 = {
    "step1": [
        f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi {doi} --level {clevel} --cat {cat} -d {server_id}', f'cat {cat}'
    ]
}

