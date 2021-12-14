#coding=utf-8

from scapy.all import *
import sys,time


def sniff_pkt(iface,filter,count,timeout=None):
    pkt = sniff(iface=iface,filter=filter,count=count,timeout=timeout)
    return pkt

while True:
    arg = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
    log.warning(arg)
    a = ' '
    filt = a.join(arg)
    log.warning(filt)
    pkt = sniff_pkt(sys.argv[1],filt,int(sys.argv[6]))
    #pkt = sniff(iface="eth1",filter="tcp",count=1)
    if len(pkt) != 0:	#如果抓到数据则写入报文，如果抓不到则不写
        wrpcap(sys.argv[7],pkt)
        time.sleep(2)
        break
    else:
        continue


