from scapy.all import *
import sys

def read(pkt,index):
    a = rdpcap(pkt)
    b = a[index][IP].options
    # log.warning(b.show())
    if b == []:
        return b
    else:
        return b[0].value

try:
    value = read(sys.argv[1],int(sys.argv[2]))
    log.warning(value)
except Exception as err:
    log.warning('待取值的报文字段不存在，请手动查看报文内容')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

