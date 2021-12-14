# coding:utf-8
from scapy.all import *


# 查看指定路径的文件目录和指定后缀的文件
def search(path='', end=''):
    try:
        if path:
            file_name = os.listdir(path)
        else:
            file_name = os.listdir()
    except Exception as err:
        sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
    else:
        if end:
            try:  # 查找path目录下以end结尾的文件
                file_name_0 = []
                for i in file_name:
                    if i.endswith(end):
                        file_name_0.append(i)
                file_name = file_name_0[:]
            except Exception as err:
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        return file_name

# 返回原始报文所有目录
base_dir = r"E:\chao\报文"
gwtest_dir = r"E:\chao\报文\new"
# # 正向报文
smac = "52:54:00:80:81:fc"
# 下一跳的mac地址
dmac = "02:4c:e3:04:9e:00"
sip = "192.168.30.71"
dip = "192.168.50.72"

# 反向报文
# smac = "52:54:00:fd:94:87"
# # 下一跳的mac地址
# dmac = "02:f9:36:ba:e1:01"
# sip = "192.168.50.72"
# dip = "192.168.30.71"
sport = 80
dport = 80

file_name = search(path=base_dir, end='pcap')  # 返回PCAP文件列表

if os.path.exists(gwtest_dir):
    pass
else:
    os.makedirs(gwtest_dir)

for f in file_name:
    # log.warning(f)
    # if "IPV4" in f and "IPV6" not in f:  # 仅对IPV4报文进行修改
    #     log.warning(f)
    #     log.warning(base_dir)
    file_path = os.path.join(base_dir, f)  # PCAP报文路径
    a = rdpcap(file_path)  # 读取报文，是一个列表
    b = a[0]  # 获取报文
    try:
        if b[Ether]:  # 如果报文是Ether格式的
            b[Ether].dst = dmac  # 修改原目的MAC
            b[Ether].src = smac
        if b[Ether].type == 2048:  # 如果是IPV4报文
            b[IP].dst = dip  # 修改源目的IP
            b[IP].src = sip
            del b[IP].chksum
            if b[IP].proto == 6:
                try:
                    del b[TCP].chksum
                except:
                    pass
            elif b[IP].proto == 17:
                try:
                    b[UDP].dport = dport
                    b[UDP].sport = sport
                    del b[UDP].chksum
                except:
                    pass
    except:
        if b[Dot3]:
            b[Dot3].dst = dmac
            b[Dot3].src = smac

    else:
        # proto_dir = os.path.join(gwtest_dir, d)
        pcap_dir = os.path.join(gwtest_dir, f)  # pcap所在目录
        wrpcap(pcap_dir, b)

