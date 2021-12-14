import time

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameOutside
ftp_ip = baseinfo.ftp_ip
windows_sip = baseinfo.windows_sip
front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid
smtp_ip = baseinfo.smtp_ip
pop3_ip = baseinfo.pop3_ip
smtp_proxy_port = baseinfo.smtp_proxy_port
pop3_proxy_port = baseinfo.pop3_proxy_port
ftp_proxy_port = baseinfo.ftp_proxy_port
http_server = baseinfo.http_server_ip
http_server_port = baseinfo.http_server_port
iso_timeout = baseinfo.iso_timeout
http_proxy_port = baseinfo.http_proxy_port
serverIp = baseinfo.BG8010ServerOpeIp
clientIp = baseinfo.BG8010ClientOpeIp
ssh_proxy_port = baseinfo.ssh_proxy_port
BG8010FrontOpeIp = baseinfo.BG8010FrontOpeIp

addsmtp_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": front_ifname,
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
            "Ifname": back_ifname,
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
            "Ifname": front_ifname,
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
            "Ifname": back_ifname,
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

addftp_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": front_ifname,
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
            "Ifname": back_ifname,
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

addtcp_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": front_ifname,
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
            "Ifname": back_ifname,
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
            "Ifname": front_ifname,
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
            "Ifname": back_ifname,
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

delsmtp_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": front_ifname,
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
        }]}
}

delsmtp_back = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": back_ifname,
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
        }]}
}

delpop3_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": front_ifname,
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
        }]}
}

delpop3_back = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": back_ifname,
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
        }]}
}

delftp_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": front_ifname,
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
            "Ifname": back_ifname,
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
