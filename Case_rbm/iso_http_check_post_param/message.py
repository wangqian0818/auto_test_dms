import time

from Case_rbm.iso_http_check_post_param import index

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameInside
windows_sip = baseinfo.windows_sip
front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid
http_server = baseinfo.http_server_ip
http_server_port = baseinfo.http_server_port
http_proxy_port = baseinfo.http_proxy_port
check1_data1 = index.check1_data1
check2_data1 = index.check2_data1
check2_data2 = index.check2_data2

addhttp_front = {
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
            "Ifname": back_ifname,
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

delhttp_front = {
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
            "Ifname": back_ifname,
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

httpcheck1 = {
    'SetHttpCheck': {
        "MethodName": "SetHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "content",
            "DataCheck": [{"method": "post", "DataType": "re", "Data": check1_data1}]}]
    }}
httpcheck2 = {
    'SetHttpCheck': {
        "MethodName": "SetHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "content",
            "DataCheck": [{"method": "post", "DataType": "re", "Data": f'{check2_data1};{check2_data2}'}]}]
    }}

delhttpcheck = {
    'DropHttpCheck': {
        "MethodName": "DropHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": []}
}
