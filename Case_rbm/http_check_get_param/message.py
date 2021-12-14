import time

from Case_rbm.http_check_get_param import index

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
proxy_ip = baseinfo.gwClientIp
proxy_port = index.proxy_port
server_ip = baseinfo.http_server_ip
server_port = baseinfo.http_server_port
check1_data1 = index.check1_data1
check2_data1 = index.check2_data1
check2_data2 = index.check2_data2

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
            "Type": "content",
            "DataCheck": [{"method": "get", "DataType": "re", "Data": check1_data1}]}]
    }}
httpcheck2 = {
    'SetHttpCheck': {
        "MethodName": "SetHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "content",
            "DataCheck": [{"method": "get", "DataType": "re", "Data": f'{check2_data1};{check2_data2}'}]}]
    }}

delhttpcheck = {
    'DropHttpCheck': {
        "MethodName": "DropHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": []}
}
