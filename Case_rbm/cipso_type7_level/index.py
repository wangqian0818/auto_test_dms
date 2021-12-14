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
type = 7
cat = '0x1,0x2,0x3,0x4'
match = 1
doi = 16
integrity = ''

'''
用例一：验证含type7标记策略的机密性和完整性都填的规则
'''
pkt1_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_level_a1_01.pcap"],
              ["0001_TCP_ETH_IPV4_TCP_7_16_15_13_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_level_a1_02.pcap"],
              ["0001_TCP_ETH_IPV4_TCP_7_16_10_12_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_level_a1_03.pcap"]]
pkt1_cfg={
    "send": [ciface, 1, pkt1_files[0][0], pkt1_files[1][0], pkt1_files[2][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt1_files[0][1], pkt1_files[1][1], pkt1_files[2][1]],
    "read": [pkt1_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case1_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '10-10',  # 机密性级别比较范围
        'Integrity': '13-13',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}

'''
用例二：验证含type7标记策略的只填机密性（BLP模型）规则 
'''
pkt2_files = [["0001_TCP_ETH_IPV4_TCP_7_16_13__0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_level_a2_01.pcap"],
              ["0001_TCP_ETH_IPV4_TCP_7_16_10__0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_level_a2_02.pcap"]]
pkt2_cfg={
    "send": [ciface, 1, pkt2_files[0][0], pkt2_files[1][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt2_files[0][1], pkt2_files[1][1]],
    "read": [pkt2_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case2_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '13-15',  # 机密性级别比较范围
        'Integrity': '',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}

'''
用例三：验证含type7标记策略的只填完整性（BIBA模型）规则 
'''
pkt3_files = [["0001_TCP_ETH_IPV4_TCP_7_16__13_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_level_a3_01.pcap"],
              ["0001_TCP_ETH_IPV4_TCP_7_16__15_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_level_a3_02.pcap"]]
pkt3_cfg={
    "send": [ciface, 1, pkt3_files[0][0], pkt3_files[1][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt3_files[0][1], pkt3_files[1][1]],
    "read": [pkt3_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case3_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '',  # 机密性级别比较范围
        'Integrity': '13-14',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}

'''
用例四：验证type7类型下的机密性和完整性密级的左边界（最小值） 
'''
pkt4_files = [["0001_TCP_ETH_IPV4_TCP_7_16_1_1_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_level_a4_01.pcap"]]
pkt4_cfg={
    "send": [ciface, 1, pkt4_files[0][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt4_files[0][1]],
    "read": [pkt4_files[0][1], 0],
    "expect": [strip, 0, 0]
}

case4_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '1-1',  # 机密性级别比较范围
        'Integrity': '1-1',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}

'''
用例五：验证type7类型下的机密性和完整性密级的右边界（最大值） 
'''
pkt5_files = [["0001_TCP_ETH_IPV4_TCP_7_16_255_255_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_level_a5_01.pcap"]]
pkt5_cfg={
    "send": [ciface, 1, pkt5_files[0][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt5_files[0][1]],
    "read": [pkt5_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case5_mtLabel = {
    'MtLabel': {
        'DOI': 16,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': match,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': '255-255',  # 机密性级别比较范围
        'Integrity': '255-255',  # 完整性级别比较范围
        'Cat': cat,  # 类别列表比较对象
    }
}