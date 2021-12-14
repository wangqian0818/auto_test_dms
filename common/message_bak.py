#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/10/26 17:04

'''
当前框架现有所有种类message
'''


import time
from common import baseinfo
from common.baseinfo import pcapReadIface

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
data = None    # 所有用到data的都是index中的特定传参
windows_sip = baseinfo.windows_sip
front_pcapReadIface = baseinfo.BG8010FrontOpepcapReadIface
back_pcapReadIface = baseinfo.BG8010BackOpepcapReadIfaceOutside
front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid
BG8010FrontOpeIp = baseinfo.BG8010FrontOpeIp
serverIp = baseinfo.BG8010ServerOpeIp
clientIp = baseinfo.BG8010ClientOpeIp

http_server = baseinfo.http_server_ip
http_server_port = baseinfo.http_server_port
http_proxy_port = baseinfo.http_proxy_port
http_server_port_file = baseinfo.http_server_port_file
http_redirect_ip = baseinfo.http_redirect_ip
http_redirect_port = baseinfo.http_redirect_port

iso_timeout = baseinfo.iso_timeout
ssh_proxy_port = baseinfo.ssh_proxy_port

dns_port = baseinfo.dns_port
dns_proxy_port = baseinfo.dns_proxy_port

ftp_ip = baseinfo.ftp_ip
ftp_proxy_port = baseinfo.ftp_proxy_port

smtp_ip = baseinfo.smtp_ip
pop3_ip = baseinfo.pop3_ip
smtp_proxy_port = baseinfo.smtp_proxy_port
pop3_proxy_port = baseinfo.pop3_proxy_port

# ACL
serverOpeIp = baseinfo.serverOpeIp
clientOpeIp = baseinfo.clientOpeIp
gwCard0 = baseinfo.gwCard0
pcapGwIface = baseinfo.pcapGwIface

addhttp_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_server_port,
                "SeLabel": {},
                "Module": "http",
                "File": "off",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addhttp_back = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_server_port,
                "SeLabel": {},
                "Module": "http",
                "File": "off",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addhttp_front_post = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 21,
                "L3protocol": "ipv4",
                "Dport": http_server_port_file,
                "SeLabel": {},
                "Module": "http",
                "File": "off",
                "Lport": http_server_port_file,
                "L4protocol": "tcp"}]
        }]}
}

addhttp_back_post = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 21,
                "L3protocol": "ipv4",
                "Dport": http_server_port_file,
                "SeLabel": {},
                "Module": "http",
                "File": "off",
                "Lport": http_server_port_file,
                "L4protocol": "tcp"}]
        }]}
}

delhttp_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_server_port,
                "Module": "http",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

delhttp_back = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_server_port,
                "Module": "http",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

delhttp_front_post = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 21,
                "L3protocol": "ipv4",
                "Dport": http_server_port_file,
                "Module": "http",
                "Lport": http_server_port_file,
                "L4protocol": "tcp"}]
        }]}
}

delhttp_back_post = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 21,
                "L3protocol": "ipv4",
                "Dport": http_server_port_file,
                "Module": "http",
                "Lport": http_server_port_file,
                "L4protocol": "tcp"}]
        }]}
}

addhttp_redirect_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": http_redirect_ip,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_redirect_port,
                "SeLabel": {},
                "Module": "http",
                "File": "off",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addhttp_redirect_back = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": http_redirect_ip,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_redirect_port,
                "SeLabel": {},
                "Module": "http",
                "File": "off",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

delhttp_redirect_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": http_redirect_ip,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_redirect_port,
                "Module": "http",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

delhttp_redirect_back = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": http_redirect_ip,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_redirect_port,
                "Module": "http",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}
# TCP ================================================================================================================
addtcp_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Action": "allow",
                "Appid": 4,
                "L3protocol": "ipv4",
                "Timeout": iso_timeout,
                "Dport": http_server_port,
                "SeLabel": {},
                "File": "off",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addtcp_back = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Action": "allow",
                "Appid": 4,
                "L3protocol": "ipv4",
                "Timeout": iso_timeout,
                "Dport": http_server_port,
                "SeLabel": {},
                "File": "off",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addtcp_ssh_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": serverIp,
            "Sip": clientIp,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Action": "allow",
                "Appid": 30,
                "L3protocol": "ipv4",
                "Timeout": iso_timeout,
                "Dport": 22,
                "SeLabel": {},
                "File": "off",
                "Lport": ssh_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addtcp_ssh_back = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": serverIp,
            "Sip": clientIp,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Action": "allow",
                "Appid": 30,
                "L3protocol": "ipv4",
                "Timeout": iso_timeout,
                "Dport": 22,
                "SeLabel": {},
                "File": "off",
                "Lport": ssh_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

# UDP ==============================================================================================================

addudp_dns_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": serverIp,
            "Sip": clientIp,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Action": "allow",
                "Appid": 5,
                "L3protocol": "ipv4",
                "Timeout": iso_timeout,
                "Dport": dns_port,
                "SeLabel": {},
                "File": "off",
                "Lport": dns_proxy_port,
                "L4protocol": "udp"}]
        }]}
}

addudp_dns_back = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": serverIp,
            "Sip": clientIp,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Action": "allow",
                "Appid": 5,
                "L3protocol": "ipv4",
                "Timeout": iso_timeout,
                "Dport": dns_port,
                "SeLabel": {},
                "File": "off",
                "Lport": dns_proxy_port,
                "L4protocol": "udp"}]
        }]}
}

deludp_dns_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": serverIp,
            "Sip": clientIp,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Action": "allow",
                "Appid": 5,
                "L3protocol": "ipv4",
                "Timeout": iso_timeout,
                "Dport": dns_port,
                "Lport": dns_proxy_port,
                "L4protocol": "udp"}]
        }]}
}

deludp_dns_back = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": serverIp,
            "Sip": clientIp,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Action": "allow",
                "Appid": 5,
                "L3protocol": "ipv4",
                "Timeout": iso_timeout,
                "Dport": dns_port,
                "Lport": dns_proxy_port,
                "L4protocol": "udp"}]
        }]}
}
# FTP ==================================================================================================================

addftp_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": ftp_ip,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 3,
                "L3protocol": "ipv4",
                "Dport": 21,
                "SeLabel": {},
                "Module": "ftp",
                "File": "off",
                "Lport": ftp_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addftp_back = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": ftp_ip,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 3,
                "L3protocol": "ipv4",
                "Pip": BG8010FrontOpeIp,
                "Dport": 21,
                "SeLabel": {},
                "Module": "ftp",
                "File": "off",
                "Lport": ftp_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}
delftp_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": ftp_ip,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 3,
                "L3protocol": "ipv4",
                "Dport": 21,
                "Module": "ftp",
                "Lport": ftp_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

delftp_back = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": ftp_ip,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 3,
                "L3protocol": "ipv4",
                "Pip": BG8010FrontOpeIp,
                "Dport": 21,
                "Module": "ftp",
                "Lport": ftp_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}
# MAIL ==================================================================================================================

addsmtp_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": smtp_ip,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 1,
                "L3protocol": "ipv4",
                "Dport": 25,
                "SeLabel": {},
                "Module": "smtp",
                "File": "off",
                "Lport": smtp_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addsmtp_back = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": smtp_ip,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 1,
                "L3protocol": "ipv4",
                "Dport": 25,
                "SeLabel": {},
                "Module": "smtp",
                "File": "off",
                "Lport": smtp_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addpop3_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": pop3_ip,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 2,
                "L3protocol": "ipv4",
                "Dport": 110,
                "SeLabel": {},
                "Module": "pop3",
                "File": "off",
                "Lport": pop3_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addpop3_back = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": pop3_ip,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 2,
                "L3protocol": "ipv4",
                "Dport": 110,
                "SeLabel": {},
                "Module": "pop3",
                "File": "off",
                "Lport": pop3_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}
delsmtp_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": smtp_ip,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 1,
                "L3protocol": "ipv4",
                "Dport": 25,
                "Module": "smtp",
                "Lport": smtp_proxy_port,
                "L4protocol": "tcp"}]
        }]
    }
}
delsmtp_back = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": smtp_ip,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 1,
                "L3protocol": "ipv4",
                "Dport": 25,
                "Module": "smtp",
                "Lport": smtp_proxy_port,
                "L4protocol": "tcp"}]
        }]
    }
}
delpop3_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": front_pcapReadIface,
            "Dip": pop3_ip,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 2,
                "L3protocol": "ipv4",
                "Dport": 110,
                "Module": "pop3",
                "Lport": pop3_proxy_port,
                "L4protocol": "tcp"}]
        }]
    }
}
delpop3_back = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "pcapReadIface": back_pcapReadIface,
            "Dip": pop3_ip,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 2,
                "L3protocol": "ipv4",
                "Dport": 110,
                "Module": "pop3",
                "Lport": pop3_proxy_port,
                "L4protocol": "tcp"}]
        }]
    }
}

dataCheck = {
    'SetMailCheck': {
        "MethodName": "SetMailCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "Subject",
            "DataCheck": data}]
    }}

delDataCheck = {
    'DropMailCheck': {
        "MethodName": "DropMailCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": []}
}

# ACL 策略【删除message都通用】==============================================================================================================
AddAclPolicy_ICMP = {
    "AddAclPolicy": {
        "MethodName": "AddAclPolicy",
        "MessageTime": datatime,
        "Content": [{
            "SeLabelDrop": "",
            "Action": "0",
            "QosMode": 0,
            "SeLabelLevel": "",
            "SeLabelBitmap": "",
            "SeLabelType": "",
            "QosThreshold": "150,150",
            "Dip": serverOpeIp,
            "pcapReadIface": "",
            "QosBucket": 1,
            "Listorder": "1",
            "Direction": "INPUT",
            "TTL": "",
            "SeLabelMatch": "",
            "Card": gwCard0,
            "SeLabelMode": "",
            "Sport": "",
            "Dport": "",
            "SeLabelTag": "",
            "Sip": clientOpeIp,
            "Protocol": "1",
            "SeLabelDoi": ""}]
    }
}

AddAclPolicy_HitCount = {
    "AddAclPolicy": {
        "MethodName": "AddAclPolicy",
        "MessageTime": datatime,
        "Content": [{
            "SeLabelDrop": "",
            "Action": "0",
            "QosMode": "",
            "SeLabelLevel": "",
            "SeLabelBitmap": "",
            "SeLabelType": "",
            "QosThreshold": "",
            "Dip": serverOpeIp,
            "pcapReadIface": pcapGwIface,
            "QosBucket": "",
            "Listorder": "1",
            "Direction": "INPUT",
            "TTL": "",
            "SeLabelMatch": "",
            "SeLabelMode": "",
            "Sport": data,
            "Dport": data,
            "SeLabelTag": "",
            "Sip": clientOpeIp,
            "Protocol": "6",
            "SeLabelDoi": ""}]
    }
}
# 下发ICMP协议的acl策略
AddAclPolicy_labelPassPac = {
    "AddAclPolicy": {
        "MethodName": "AddAclPolicy",
        "MessageTime": datatime,
        "Content": [{
            "SeLabelDrop": "",
            "Action": "0",
            "QosMode": "",
            "SeLabelLevel": "",
            "SeLabelBitmap": "",
            "SeLabelType": "",
            "QosThreshold": "",
            "Dip": serverOpeIp,
            "pcapReadIface": pcapReadIface,
            "QosBucket": "",
            "Listorder": "1",
            "Direction": "INPUT",
            "TTL": "",
            "SeLabelMatch": "",
            "Card": gwCard0,
            "SeLabelMode": "",
            "Sport": "",
            "Dport": "",
            "SeLabelTag": "",
            "Sip": clientOpeIp,
            "Protocol": "1",
            "SeLabelDoi": ""}]}
}

# 下发UDP协议的acl策略
AddAclPolicy_labelRejectPac = {
    "AddAclPolicy": {
        "MethodName": "AddAclPolicy",
        "MessageTime": datatime,
        "Content": [{
            "SeLabelDrop": "",
            "Action": "0",
            "QosMode": "",
            "SeLabelLevel": "",
            "SeLabelBitmap": "",
            "SeLabelType": "",
            "QosThreshold": "",
            "Dip": serverOpeIp,
            "pcapReadIface": pcapReadIface,
            "QosBucket": "",
            "Listorder": "1",
            "Direction": "INPUT",
            "TTL": "",
            "SeLabelMatch": "",
            "Card": gwCard0,
            "SeLabelMode": "",
            "Sport": data,
            "Dport": data,
            "SeLabelTag": "",
            "Sip": clientOpeIp,
            "Protocol": "17",
            "SeLabelDoi": ""
        }]}
}
AddAclPolicy_UDP = {
    "AddAclPolicy": {
        "MethodName": "AddAclPolicy",
        "MessageTime": datatime,
        "Content": [{
            "SeLabelDrop": "",
            "Action": "0",
            "QosMode": 0,
            "SeLabelLevel": "",
            "SeLabelBitmap": "",
            "SeLabelType": "",
            "QosThreshold": "300,300",
            "Dip": serverOpeIp,
            "pcapReadIface": "",
            "QosBucket": 1,
            "Listorder": "1",
            "Direction": "INPUT",
            "TTL": "",
            "SeLabelMatch": "",
            "Card": gwCard0,
            "SeLabelMode": "",
            "Sport": "",
            "Dport": data,
            "SeLabelTag": "",
            "Sip": clientOpeIp,
            "Protocol": "17",
            "SeLabelDoi": ""}]
    }
}
AddAclPolicy_labelRejectPac1 = {
    "AddAclPolicy": {
        "MethodName": "AddAclPolicy",
        "MessageTime": datatime,
        "Content": [{
            "SeLabelDrop": 1,
            "Action": "0",
            "QosMode": "",
            "SeLabelLevel": '1',
            "SeLabelBitmap": '0x3,0x0,0x0,0x0',  # '0x3,0x0,0x0,0x0'
            "SeLabelType": 1,
            "QosThreshold": "",
            "Dip": serverOpeIp,
            "pcapReadIface": pcapReadIface,
            "QosBucket": "",
            "Listorder": "1",
            "Direction": "INPUT",
            "TTL": "",
            "SeLabelMatch": 1,
            "Card": gwCard0,
            "SeLabelMode": "BLP",
            "Sport": data,
            "Dport": data,
            "SeLabelTag": 2,
            "Sip": clientOpeIp,
            "Protocol": "6",
            "SeLabelDoi": 16
        }]}
}

AddAclPolicy_labelPassPac1 = {
    "AddAclPolicy": {
        "MethodName": "AddAclPolicy",
        "MessageTime": datatime,
        "Content": [{
            "SeLabelDrop": 1,
            "Action": "0",
            "QosMode": "",
            "SeLabelLevel": 14,
            "SeLabelBitmap": '0x3,0x0,0x0,0x0',  # '0x3,0x0,0x0,0x0'
            "SeLabelType": 1,
            "QosThreshold": "",
            "Dip": serverOpeIp,
            "pcapReadIface": pcapReadIface,
            "QosBucket": "",
            "Listorder": "1",
            "Direction": "INPUT",
            "TTL": "",
            "SeLabelMatch": 1,
            "Card": gwCard0,
            "SeLabelMode": "BLP",
            "Sport": data,
            "Dport": data,
            "SeLabelTag": 2,
            "Sip": clientOpeIp,
            "Protocol": "6",
            "SeLabelDoi": 16
        }]}
}
AddAclPolicy_QosData = {
    "AddAclPolicy": {
        "MethodName": "AddAclPolicy",
        "MessageTime": datatime,
        "Content": [{
            "SeLabelDrop": "",
            "Action": "0",
            "QosMode": 1,
            "SeLabelLevel": "",
            "SeLabelBitmap": "",
            "SeLabelType": "",
            "QosThreshold": '1000,100',
            "Dip": serverOpeIp,
            "pcapReadIface": pcapReadIface,
            "QosBucket": 0,
            "Listorder": "1",
            "Direction": "INPUT",
            "TTL": "",
            "SeLabelMatch": "",
            "Card": gwCard0,
            "SeLabelMode": "",
            "Sport": data,
            "Dport": data,
            "SeLabelTag": "",
            "Sip": clientOpeIp,
            "Protocol": "6",
            "SeLabelDoi": ""
        }]}
}
AddAclPolicy_QosRate = {
    "AddAclPolicy": {
        "MethodName": "AddAclPolicy",
        "MessageTime": datatime,
        "Content": [{
            "SeLabelDrop": "",
            "Action": "0",
            "QosMode": 0,
            "SeLabelLevel": "",
            "SeLabelBitmap": "",
            "SeLabelType": "",
            "QosThreshold": '300,300',
            "Dip": serverOpeIp,
            "pcapReadIface": pcapReadIface,
            "QosBucket": 0,
            "Listorder": "1",
            "Direction": "INPUT",
            "TTL": "",
            "SeLabelMatch": "",
            "Card": gwCard0,
            "SeLabelMode": "",
            "Sport": data,
            "Dport": data,
            "SeLabelTag": "",
            "Sip": clientOpeIp,
            "Protocol": "6",
            "SeLabelDoi": ""
        }]}
}
