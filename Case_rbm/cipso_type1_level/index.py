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
type = 1
cat = '0x1,0x2,0x3,0x4'
match = 1
doi = 16
integrity = ''
clevel1 = 1
slevel1 = f'{clevel1}-{clevel1}'
clevel2 = 255
slevel2 = f'{clevel2}-{clevel2}'
slevel3 = '13-16'



'''
用例一：验证type1标记的机密性等级（level）的左边界（最小值）
'''
pkt1_files = [["0001_TCP_ETH_IPV4_TCP_1_16_1_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type1_level_a1_01.pcap"]]
pkt1_cfg={
    "send": [ciface, 1, pkt1_files[0][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt1_files[0][1]],
    "read": [pkt1_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case1_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel1,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}

'''
用例二：验证type1标记的机密性等级（level）的右边界（最大值）
'''
pkt2_files = [["0001_TCP_ETH_IPV4_TCP_1_16_255_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type1_level_a2_01.pcap"]]
pkt2_cfg={
    "send": [ciface, 1, pkt2_files[0][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt2_files[0][1]],
    "read": [pkt2_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case2_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel2,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}


'''
用例三：验证含type1标记策略的机密性（BLP模型）规则
'''

pkt3_files = [["0001_TCP_ETH_IPV4_TCP_1_16_13_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type1_level_a3_01.pcap"],
              ["0001_TCP_ETH_IPV4_TCP_1_16_16_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type1_level_a3_02.pcap"],
              ["0001_TCP_ETH_IPV4_TCP_1_16_15_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type1_level_a3_03.pcap"],
              ["0001_TCP_ETH_IPV4_TCP_1_16_12_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type1_level_a3_04.pcap"]]
pkt3_cfg={
    "send": [ciface, 1, pkt3_files[0][0], pkt3_files[1][0], pkt3_files[2][0], pkt3_files[3][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt3_files[0][1], pkt3_files[1][1], pkt3_files[2][1], pkt3_files[3][1]],
    "read": [pkt3_files[0][1], pkt3_files[1][1], pkt3_files[2][1], pkt3_files[3][1], 0],
    "expect": [strip, 0, 0]
}
case3_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel3,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}
