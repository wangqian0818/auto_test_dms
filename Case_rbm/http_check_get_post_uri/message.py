import time

from Case_rbm.http_check_get_post_uri import index

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
proxy_ip = baseinfo.gwClientIp
proxy_port = index.proxy_port
server_ip = baseinfo.http_server_ip
server_port = baseinfo.http_server_port
get1_data1 = index.get1_data1
get1_data2 = index.get1_data2
post1_data1 = index.post1_data1
post1_data2 = index.post1_data2
check1_uri1 = index.check1_uri1
check1_uri2 = index.check1_uri2

addhttp = {
    'AddAgent': {
        "MethodName": "AddAgent",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "InProtocol": "http",
            "Type": 2,
            "InPort": proxy_port,
            "domain": "all",
            "SyncId": 27,
            "OutAddr": [{
                "OutPort": server_port,
                "OutIp": server_ip}],
            "InIp": proxy_ip}]
    }}
delhttp = {
    'DelAgent': {
        "MethodName": "DelAgent",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "InProtocol": "http",
            "Type": 2,
            "InPort": proxy_port,
            "domain": "all",
            "SyncId": 27,
            "OutAddr": [{
                "OutPort": server_port,
                "OutIp": server_ip}],
            "InIp": proxy_ip}]
    }}
httpcheck1 = {
    'SetHttpCheck': {
        "MethodName": "SetHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "uri", "DataCheck": [{"DataType": "re", "Data": f"{check1_uri1};{check1_uri2}"}]},
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
