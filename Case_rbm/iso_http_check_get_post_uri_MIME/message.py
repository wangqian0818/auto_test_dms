import time

from Case_rbm.iso_http_check_get_post_uri_MIME import index

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
get1_data1 = index.get1_data1
get1_data2 = index.get1_data2
post1_data1 = index.post1_data1
post1_data2 = index.post1_data2
check1_uri1 = index.check1_uri1
check1_uri2 = index.check1_uri2
MIME1_uri1 = index.MIME1_uri1
MIME1_uri2 = index.MIME1_uri2

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
            "Type": "uri", "DataCheck": [{"DataType": "re", "Data": f"{check1_uri1};{check1_uri2}"}]},
            {"Type": "mime", "DataCheck": [{"Action": 0, "Data": f"{MIME1_uri1};{MIME1_uri2}"}]},
            {"Type": "content", "DataCheck": [
                {"method": "get", "DataType": "re", "Data": f"{get1_data1};{get1_data2}"},
                {"method": "post", "DataType": "re", "Data": f"{post1_data1};{post1_data2}"}
            ]}]
    }}
httpcheck2 = {
    'SetHttpCheck': {
        "MethodName": "SetHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "uri", "DataCheck": [{"DataType": "re", "Data": f"{check1_uri1};{check1_uri2}"}]},
            {"Type": "mime", "DataCheck": [{"Action": 1, "Data": f"{MIME1_uri1};{MIME1_uri2}"}]},
            {"Type": "content", "DataCheck": [
                {"method": "get", "DataType": "re", "Data": f"{get1_data1};{get1_data2}"},
                {"method": "post", "DataType": "re", "Data": f"{post1_data1};{post1_data2}"}
            ]}]
    }}

delhttpcheck = {
    'DropHttpCheck': {
        "MethodName": "DropHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": []}
}
