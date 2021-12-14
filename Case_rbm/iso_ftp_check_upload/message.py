import time

from Case_rbm.iso_ftp_check_upload import index

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameOutside
ftp_ip = baseinfo.ftp_ip
windows_sip = baseinfo.windows_sip
front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid
ftp_proxy_port = baseinfo.ftp_proxy_port
case1_upload = index.case1_upload
case2_upload = index.case2_upload
case2_allow_upload = index.case2_allow_upload
BG8010FrontOpeIp = baseinfo.BG8010FrontOpeIp

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

ftpcheck1 = {'SetFtpCheck': {
    "MethodName": "SetFtpCheck",
    "MessageTime": datatime,
    "Sender": "Centre0",
    "Content": [{
        "Type": "upload", "DataCheck": case1_upload}
    ]}
}
ftpcheck2 = {'SetFtpCheck': {
    "MethodName": "SetFtpCheck",
    "MessageTime": datatime,
    "Sender": "Centre0",
    "Content": [{
        "Type": "upload", "DataCheck": f'{case2_upload};{case2_allow_upload}'}
    ]}
}

delftpcheck = {'DropFtpCheck': {
    "MethodName": "DropFtpCheck",
    "MessageTime": datatime,
    "Sender": "Centre0",
    "Content": []
}}
