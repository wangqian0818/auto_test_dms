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
doi = 16
slevel = '10-10'
integrity = '13-13'
cat1 = '0x3,0x2,0x3,0x4'  # 子集
cat2 = '0xa,0x2,0x7,0x9'  # 交集
cat3 = '0x2,0x0,0x0,0x1'  # 不相交
cat4 = '0x1,0x2,0x3,0x4'  # 等于
cat5 = '0x0,0x0,0x0,0x0'  # 最小值
cat6 = '0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffff'  # 最大值 type7的长度与type1不一样
cat7 = '0xffffffffffffffff,0x0,0x0,0x0'
cat8 = '0xffffffffffffffff,0xffffffffffffffff,0x0,0x0'
cat9 = '0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0x0'
cat10 = '0x0,0xffffffffffffffff,0xffffffffffffffff,0xffffffffff'
cat11 = '0xffffffffffffffff,0x0,0xffffffffffffffff,0xffffffffff'
cat12 = '0xffffffffffffffff,0xffffffffffffffff,0x0,0xffffffffff'

'''
用例一：验证含type7标记策略的类别在子集比对方式下的规则
'''

pkt1_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_cat_a1_01.pcap"]]
pkt1_cfg={
    "send": [ciface, 1, pkt1_files[0][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt1_files[0][1]],
    "read": [pkt1_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case1_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 0,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat1,  # 类别列表比较对象
    }
}

'''
用例二：验证含type7标记策略的类别在交集比对方式下的规则
'''

pkt2_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_cat_a2_01.pcap"]]
pkt2_cfg={
    "send": [ciface, 1, pkt2_files[0][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt2_files[0][1]],
    "read": [pkt2_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case2_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat2,  # 类别列表比较对象
    }
}

'''
用例三：验证含type7标记策略的类别在非比对方式下的规则
'''

pkt3_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_cat_a3_01.pcap"]]
pkt3_cfg={
    "send": [ciface, 1, pkt3_files[0][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt3_files[0][1]],
    "read": [pkt3_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case3_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 3,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat3,  # 类别列表比较对象
    }
}

'''
用例四：验证含type7标记策略的类别在等于比对方式下的规则
'''

pkt4_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0x1,0x2,0x3,0x4_P80.pcap", "test_cipso_type7_cat_a4_01.pcap"]]
pkt4_cfg={
    "send": [ciface, 1, pkt4_files[0][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt4_files[0][1]],
    "read": [pkt4_files[0][1], 0],
    "expect": [strip, 0, 0]
}
case4_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 2,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat4,  # 类别列表比较对象
    }
}

'''
用例五：验证type7类型下的类别左边界（最小）值
'''

pkt5_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0x0,0x0,0x0,0x0_P80.pcap", "test_cipso_type7_cat_a5_01.pcap"],
              ["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0x0,0x0,0x0,0x0_P80.pcap", "test_cipso_type7_cat_a5_02.pcap"]]
value5 = r"b'\x00\x00\x00\x10\x07\x05\x03\n\r'"
pkt5_cfg={
    "send": [ciface, 1, pkt5_files[0][0], pkt5_files[1][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt5_files[0][1], pkt5_files[1][1]],
    "read": [pkt5_files[0][1], pkt5_files[1][1], 0],
    "expect": [strip, f'{value5}\n', 0]
}
case5_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat5,  # 类别列表比较对象
    }
}
case5_tgLabel = {
    'TgLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Sensitivity': '10',  # 机密性级别，数值字符串，数值小于255
        'Integrity': '13',  # 完整性级别，数值字符串，数值小于255
        'Cat': cat5,  # 类别列表比较对象
    }
}

'''
用例六：验证type7类型下的类别右边界（最大）值
'''

pkt6_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
               "test_cipso_type7_cat_a6_01.pcap"],
              [ "0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
                  "test_cipso_type7_cat_a6_02.pcap"]]
val6 = r'\x00\x00\x00\x10\x07"\x07\n\r\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
value6 = r"b'" + val6 + r"'"
pkt6_cfg={
    "send": [ciface, 1, pkt6_files[0][0], pkt6_files[1][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt6_files[0][1], pkt6_files[1][1]],
    "read": [pkt6_files[0][1], pkt6_files[1][1], 0],
    "expect": [strip, f'{value6}\n', 0]
}
case6_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat6,  # 类别列表比较对象
    }
}
case6_tgLabel = {
    'TgLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Sensitivity': '10',  # 机密性级别，数值字符串，数值小于255
        'Integrity': '13',  # 完整性级别，数值字符串，数值小于255
        'Cat': cat6,  # 类别列表比较对象
    }
}

'''
用例七：验证type7类型下的类别为f000时，对报文的处理原则
'''

pkt7_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
               "test_cipso_type7_cat_a7_01.pcap"],
              [ "0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
                  "test_cipso_type7_cat_a7_02.pcap"]]
value7 = r"b'\x00\x00\x00\x10\x07\r\x07\n\r\xff\xff\xff\xff\xff\xff\xff\xff'"
pkt7_cfg={
    "send": [ciface, 1, pkt7_files[0][0], pkt7_files[1][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt7_files[0][1], pkt7_files[1][1]],
    "read": [pkt7_files[0][1], pkt7_files[1][1], 0],
    "expect": [strip, f'{value7}\n', 0]
}
case7_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat7,  # 类别列表比较对象
    }
}
case7_tgLabel = {
    'TgLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Sensitivity': '10',  # 机密性级别，数值字符串，数值小于255
        'Integrity': '13',  # 完整性级别，数值字符串，数值小于255
        'Cat': cat7,  # 类别列表比较对象
    }
}

'''
用例八：验证type7类型下的类别为ff00时，对报文的处理原则
'''

pkt8_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
               "test_cipso_type7_cat_a8_01.pcap"],
              [ "0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
                  "test_cipso_type7_cat_a8_02.pcap"]]
value8 = r"b'\x00\x00\x00\x10\x07\x15\x07\n\r\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"
pkt8_cfg={
    "send": [ciface, 1, pkt8_files[0][0], pkt8_files[1][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt8_files[0][1], pkt8_files[1][1]],
    "read": [pkt8_files[0][1], pkt8_files[1][1], 0],
    "expect": [strip, f'{value8}\n', 0]
}
case8_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat8,  # 类别列表比较对象
    }
}
case8_tgLabel = {
    'TgLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Sensitivity': '10',  # 机密性级别，数值字符串，数值小于255
        'Integrity': '13',  # 完整性级别，数值字符串，数值小于255
        'Cat': cat8,  # 类别列表比较对象
    }
}

'''
用例九：验证type7类型下的类别为fff0时，对报文的处理原则
'''

pkt9_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
               "test_cipso_type7_cat_a9_01.pcap"],
              [ "0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
                  "test_cipso_type7_cat_a9_02.pcap"]]
value9 = r"b'\x00\x00\x00\x10\x07\x1d\x07\n\r\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"
pkt9_cfg={
    "send": [ciface, 1, pkt9_files[0][0], pkt9_files[1][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt9_files[0][1], pkt9_files[1][1]],
    "read": [pkt9_files[0][1], pkt9_files[1][1], 0],
    "expect": [strip, f'{value9}\n', 0]
}
case9_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat9,  # 类别列表比较对象
    }
}
case9_tgLabel = {
    'TgLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Sensitivity': '10',  # 机密性级别，数值字符串，数值小于255
        'Integrity': '13',  # 完整性级别，数值字符串，数值小于255
        'Cat': cat9,  # 类别列表比较对象
    }
}

'''
用例十：验证type7类型下的类别为0fff时，对报文的处理原则
'''

pkt10_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
               "test_cipso_type7_cat_a10_01.pcap"],
              [ "0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
                  "test_cipso_type7_cat_a10_02.pcap"]]
val10 = r'\x00\x00\x00\x10\x07"\x07\n\r\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
value10 = r"b'" + val10 + r"'"
pkt10_cfg={
    "send": [ciface, 1, pkt10_files[0][0], pkt10_files[1][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt10_files[0][1], pkt10_files[1][1]],
    "read": [pkt10_files[0][1], pkt10_files[1][1], 0],
    "expect": [strip, f'{value10}\n', 0]
}
case10_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat10,  # 类别列表比较对象
    }
}
case10_tgLabel = {
    'TgLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Sensitivity': '10',  # 机密性级别，数值字符串，数值小于255
        'Integrity': '13',  # 完整性级别，数值字符串，数值小于255
        'Cat': cat10,  # 类别列表比较对象
    }
}


'''
用例十一：验证type7类型下的类别为f0ff时，对报文的处理原则
'''

pkt11_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
               "test_cipso_type7_cat_a11_01.pcap"],
              [ "0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
                  "test_cipso_type7_cat_a11_02.pcap"]]
val11 = r'\x00\x00\x00\x10\x07"\x07\n\r\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
value11 = r"b'" + val11 + r"'"
pkt11_cfg={
    "send": [ciface, 1, pkt11_files[0][0], pkt11_files[1][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt11_files[0][1], pkt11_files[1][1]],
    "read": [pkt11_files[0][1], pkt11_files[1][1], 0],
    "expect": [strip, f'{value11}\n', 0]
}
case11_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat11,  # 类别列表比较对象
    }
}
case11_tgLabel = {
    'TgLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Sensitivity': '10',  # 机密性级别，数值字符串，数值小于255
        'Integrity': '13',  # 完整性级别，数值字符串，数值小于255
        'Cat': cat11,  # 类别列表比较对象
    }
}

'''
用例十二：验证type7类型下的类别为ff0f时，对报文的处理原则
'''

pkt12_files = [["0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
               "test_cipso_type7_cat_a12_01.pcap"],
              [ "0001_TCP_ETH_IPV4_TCP_7_16_10_13_0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff_P80.pcap",
                  "test_cipso_type7_cat_a12_02.pcap"]]
val12 = r'\x00\x00\x00\x10\x07"\x07\n\r\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff'
value12 = r"b'" + val12 + r"'"
pkt12_cfg={
    "send": [ciface, 1, pkt12_files[0][0], pkt12_files[1][0]],
    "capture": [siface, f'tcp and host {cipso_dip}', 1, pkt12_files[0][1], pkt12_files[1][1]],
    "read": [pkt12_files[0][1], pkt12_files[1][1], 0],
    "expect": [strip, f'{value12}\n', 0]
}
case12_mtLabel = {
    'MtLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Match': 1,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
        'Sensitivity': slevel,  # 机密性级别比较范围
        'Integrity': integrity,  # 完整性级别比较范围
        'Cat': cat12,  # 类别列表比较对象
    }
}
case12_tgLabel = {
    'TgLabel': {
        'DOI': doi,  # Doi
        'Type': type,  # 解释域，整形，取值1~UINT32_MAX
        'Sensitivity': '10',  # 机密性级别，数值字符串，数值小于255
        'Integrity': '13',  # 完整性级别，数值字符串，数值小于255
        'Cat': cat12,  # 类别列表比较对象
    }
}