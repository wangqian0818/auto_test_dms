import time

from Case_rbm.ftp_check_download import index

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
proxy_ip = baseinfo.gwClientIp
ftp_ip = baseinfo.ftp_ip
case1_downfile = index.case1_downfile
case2_downfile = index.case2_downfile
case2_allow_downfile = index.case2_allow_downfile
ftp_proxy_port = baseinfo.ftp_proxy_port

addftp = {
    'AddAgent': {
        "MethodName": "AddAgent",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "InProtocol": "ftp",
            "Type": 2,
            "InPort": ftp_proxy_port,
            "domain": "all",
            "SyncId": 87,
            "OutAddr": [{"OutPort": 21, "OutIp": ftp_ip}],
            "InIp": proxy_ip
        }]
    }}
delftp = {
    'DelAgent': {
        "MethodName": "DelAgent",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "InProtocol": "ftp",
            "Type": 2,
            "InPort": ftp_proxy_port,
            "domain": "all",
            "SyncId": 87,
            "OutAddr": [{"OutPort": 21, "OutIp": ftp_ip}],
            "InIp": proxy_ip
        }]}
}
ftpcheck1 = {'SetFtpCheck': {
    "MethodName": "SetFtpCheck",
    "MessageTime": datatime,
    "Sender": "Centre0",
    "Content": [{
        "Type": "download", "DataCheck": case1_downfile}
    ]}
}
ftpcheck2 = {'SetFtpCheck': {
    "MethodName": "SetFtpCheck",
    "MessageTime": datatime,
    "Sender": "Centre0",
    "Content": [{
        "Type": "download", "DataCheck": f'{case2_downfile};{case2_allow_downfile}'}
    ]}
}

delftpcheck = {'DropFtpCheck': {
    "MethodName": "DropFtpCheck",
    "MessageTime": datatime,
    "Sender": "Centre0",
    "Content": []
}}
