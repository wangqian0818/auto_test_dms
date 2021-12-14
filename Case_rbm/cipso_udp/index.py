# coding:utf-8
from common import baseinfo
import random

# 共用参数设置
cipso_sip = baseinfo.clientOpeIp
cipso_dip = baseinfo.serverOpeIp
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface
strip = baseinfo.strip

dport = baseinfo.http_server_port
cat = '0x1,0x2,0x3,0x4'
match = 1
'''
用例一：验证含type1标记对UDP报文的去标
'''
# 报文发送,读取和预期结果
# 列表里面的命令依次为：
# 1.发送端：发送报文接口，发送报文数量，发送报文名称；
# 2.抓包：接口名称，过滤规则，抓包数量，报文命名（以用例名称.pcap命名）
# 3.报文读取：保存的报文名称，要读取的包的序号；这里读取的报文名称和上面抓包的保存报文名称应该一致
# 4.期望结果：预期结果（协议字段），是否有偏差（保留），偏差值（保留）
pkt1_files = [["0001_UDP_ETH_IPV4_UDP_1_16_13_0x1,0x2,0x3,0x4_P80.pcap", "test_udp_type1_a1_01.pcap"]]
pkt1_cfg={
    "send": [ciface, 1, pkt1_files[0][0]],
    "capture": [siface, f'udp and host {cipso_dip}', 1, pkt1_files[0][1]],
    "read": [pkt1_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case1_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': 1,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '13-13',  # 机密性级别比较范围
        'Integrity': '',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}

'''
用例二：验证含type7标记对UDP报文的去标
'''
pkt2_files = [["0001_UDP_ETH_IPV4_UDP_7_16_10_13_0x1,0x2,0x3,0x4_P80.pcap", "test_udp_type7_a2_01.pcap"]]
pkt2_cfg={
    "send": [ciface, 1, pkt2_files[0][0]],
    "capture": [siface, f'udp and host {cipso_dip}', 1, pkt2_files[0][1]],
    "read": [pkt2_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case2_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': 7,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '10-10',  # 机密性级别比较范围
        'Integrity': '13-13',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}

'''
用例三：验证标记对udp报文的完整通信
'''
pkt3_files = [["0001_UDP_ETH_IPV4_UDP_1_16_13_0x1,0x2,0x3,0x4_P80.pcap", "test_udp_type1_a3_01.pcap"],
              ["0002_UDP_ETH_IPV4_UDP_1_16_13_0x1,0x2,0x3,0x4_P80.pcap", "test_udp_type1_a3_02.pcap"]]
value3 = r"b'\x00\x00\x00\x10\x01\x1d\x00\r\x80\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x00 '"
pkt3_cfg={
    "send": [ciface, 1, pkt3_files[0][0], pkt3_files[1][0]],
    "capture": [siface, f'udp and host {cipso_dip}', 1, pkt3_files[0][1], pkt3_files[1][1]],
    "read": [pkt3_files[0][1], pkt3_files[1][1], 0],
    "expect": [strip, f'{value3}\n', 0]
}
case3_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': 1,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '10-10',  # 机密性级别比较范围
        'Integrity': '13-13',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}

