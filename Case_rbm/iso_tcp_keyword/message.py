import time

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameOutside
smtp_ip = baseinfo.smtp_ip
pop3_ip = baseinfo.pop3_ip
ftp_ip = baseinfo.ftp_ip
windows_sip = baseinfo.windows_sip
front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid
smtp_proxy_port = baseinfo.smtp_proxy_port
pop3_proxy_port = baseinfo.pop3_server_port
ftp_proxy_port = baseinfo.ftp_proxy_port
http_server = baseinfo.http_server_ip
http_server_port = baseinfo.http_server_port
iso_timeout = baseinfo.iso_timeout
http_proxy_port = baseinfo.http_proxy_port
serverIp = baseinfo.BG8010ServerOpeIp
clientIp = baseinfo.BG8010ClientOpeIp
ssh_proxy_port = baseinfo.ssh_proxy_port
BG8010FrontOpeIp = baseinfo.BG8010FrontOpeIp
smtp_keyword = "cGF0dGVybj0iNVkyVDZLNnYiIGZsYWdzPSJGTEFHX0NBU0VMRVNTIg0K"  # 卓讯的base64编码的file
pop3_keyword = "cGF0dGVybj0iNTZlUjVvcUEiIGZsYWdzPSJGTEFHX0NBU0VMRVNTIg0K"  # 科技的base64编码的file
ftp_keyword = 'cGF0dGVybj0iUkVUUiIgZmxhZ3M9IkZMQUdfQ0FTRUxFU1MiDQo='  # RETR的file
http_keyword = 'cGF0dGVybj0iZ2V0IiBmbGFncz0iRkxBR19DQVNFTEVTUyINCg=='  # get的file

add_kw_smtp_front = {
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
                "File": smtp_keyword,
                "Lport": smtp_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

add_kw_smtp_back = {
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
                "File": smtp_keyword,
                "Lport": smtp_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

add_kw_pop3_front = {
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
                "File": pop3_keyword,
                "Lport": pop3_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

add_kw_pop3_back = {
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
                "File": pop3_keyword,
                "Lport": pop3_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

add_kw_ftp_front = {
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
                "File": ftp_keyword,
                "Lport": ftp_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

add_kw_ftp_back = {
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
                "File": ftp_keyword,
                "Lport": ftp_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

add_kw_tcp_front = {
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
                "File": http_keyword,
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

add_kw_tcp_back = {
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
                "File": http_keyword,
                "Lport": http_proxy_port,
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
        }]
    }
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
        }]
    }
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
        }]
    }
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
        }]
    }
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

deltcp_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
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
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

deltcp_back = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
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
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}
