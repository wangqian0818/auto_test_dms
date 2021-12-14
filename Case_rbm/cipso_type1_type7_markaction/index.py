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

'''
用例一：验证网关设备将type1标记和type7标记互相转换的情况
'''
# 报文发送,读取和预期结果
# 列表里面的命令依次为：
# 1.发送端：发送报文接口，发送报文数量，发送报文名称；
# 2.抓包：接口名称，过滤规则，抓包数量，报文命名（以用例名称.pcap命名）
# 3.报文读取：保存的报文名称，要读取的包的序号；这里读取的报文名称和上面抓包的保存报文名称应该一致
# 4.期望结果：预期结果（协议字段），是否有偏差（保留），偏差值（保留）
pkt1_files = [["0001_TCP_ETH_IPV4_TCP_1_16_13_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type1_type7_markaction_a1_01.pcap"]]
value1 = r"b'\x00\x00\x00\x10\x07\x1e\x07\n\r\x80\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x00 '"
pkt1_cfg={
    "send": [ciface, 1, pkt1_files[0][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt1_files[0][1]],
    "read": [pkt1_files[0][1], 0],
    "expect": [f'{value1}\n', 0, 0]
}
case1_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': 1,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '13-13',  # 机密性级别比较范围
        'Integrity': '',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}
case1_tgLabel = {
    'TgLabel': {
        'DOI': 16,  # Doi
        'Type': 7,  # 解释域，整形，取值1~UINT32_MAX
        'Sensitivity': '10',  # 机密性级别，数值字符串，数值小于255
        'Integrity': '13',  # 完整性级别，数值字符串，数值小于255
        'Cat': cat,  # 类别列表比较对象
    }

}

'''
用例二：验证网关设备会话为type1标记，反向会话为type7标记时的情况
'''
pkt2_files = [["0001_TCP_ETH_IPV4_TCP_1_16_13_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type1_type7_markaction_a2_01.pcap"]]
value2 = r"b'\x00\x00\x00\x10\x07\x1e\x03\n\r\x80\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x00 '"
pkt2_cfg={
    "send": [ciface, 1, pkt2_files[0][0]],
    "capture": [ciface, f'tcp and host {cipso_dip}', 1, pkt2_files[0][1]],
    "read": [pkt2_files[0][1], 0],
    "expect": [f'{value2}\n', 0, 0]
}
case2_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': 1,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '13-13',  # 机密性级别比较范围
        'Integrity': '',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}
case2_rvTgLabel = {
    'RvTgLabel': {
        'DOI': 16,  # Doi
        'Type': 7,  # 解释域，整形，取值1~UINT32_MAX
        'Sensitivity': '10',  # 机密性级别，数值字符串，数值小于255
        'Integrity': '13',  # 完整性级别，数值字符串，数值小于255
        'Cat': cat,  # 类别列表比较对象
    }

}
