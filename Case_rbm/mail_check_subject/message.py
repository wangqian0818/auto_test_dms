import time

from Case_rbm.mail_check_subject import index

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
proxy_ip = baseinfo.gwClientIp
smtp_ip = baseinfo.smtp_ip
pop3_ip = baseinfo.pop3_ip
ftp_ip = baseinfo.ftp_ip
smtp_proxy_port = baseinfo.smtp_proxy_port
pop3_proxy_port = baseinfo.pop3_proxy_port
mail_sender = index.mail_sender
case1_title1 = index.case1_title1
case2_title1 = index.case2_title1
case2_title2 = index.case2_title2

addsmtp = {
    'AddAgent': {
        "MethodName": "AddAgent",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "InProtocol": "smtp",
            "Type": 2,
            "InPort": smtp_proxy_port,
            "domain": "all",
            "SyncId": 85,
            "OutAddr": [{"OutPort": 25, "OutIp": smtp_ip}],
            "InIp": proxy_ip
        }]
    }}
addpop3 = {
    'AddAgent': {
        "MethodName": "AddAgent",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "InProtocol": "pop3",
            "Type": 2,
            "InPort": pop3_proxy_port,
            "domain": "all",
            "SyncId": 86,
            "OutAddr": [{"OutPort": 110, "OutIp": pop3_ip}],
            "InIp": proxy_ip
        }]
    }}
delsmtp = {'DelAgent': {
    "MethodName": "DelAgent",
    "MessageTime": datatime,
    "Sender": "Centre0",
    "Content": [{
        "InProtocol": "smtp",
        "Type": 2,
        "InPort": smtp_proxy_port,
        "domain": "all",
        "SyncId": 85,
        "OutAddr": [{"OutPort": 25, "OutIp": smtp_ip}],
        "InIp": proxy_ip
    }]
}}
delpop3 = {
    'DelAgent': {
        "MethodName": "DelAgent",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "InProtocol": "pop3",
            "Type": 2,
            "InPort": pop3_proxy_port,
            "domain": "all",
            "SyncId": 86,
            "OutAddr": [{"OutPort": 110, "OutIp": pop3_ip}],
            "InIp": proxy_ip
        }]
    }}
mailcheck1 = {
    'SetMailCheck': {
        "MethodName": "SetMailCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "Subject",
            "DataCheck": case1_title1}]
    }}
mailcheck2 = {
    'SetMailCheck': {
        "MethodName": "SetMailCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "Subject",
            "DataCheck": f'{case2_title1};{case2_title2}'}]
    }}

delmailcheck = {
    'DropMailCheck': {
        "MethodName": "DropMailCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": []}
}
