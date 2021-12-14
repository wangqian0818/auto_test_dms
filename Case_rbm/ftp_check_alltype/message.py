import time

from Case_rbm.ftp_check_alltype import index

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
proxy_ip = baseinfo.gwClientIp
ftp_ip = baseinfo.ftp_ip
allow_user = baseinfo.ftp_user
case1_upload = index.case1_upload
case1_downfile = index.case1_downfile
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
        "Type": "user", "DataCheck": allow_user},
        {"Type": "cmd",
         "DataCheck": "ABOR;ACCT;ADAT;ALLO;APPE;AUTH;CCC;CDUP;CONF;CWD;DELE;ENC;EPRT;EPSV;FEAT;HELP;LANG;LIST;LPRT;LPSV;MDTM;MIC;MKD;MLSD;MLST;MODE;NLST;NOOP;OPTS;PASS;PASV;PBSZ;PORT;PROT;PWD;QUIT;REIN;REST;RMD;RNFR;RNTO;SITE;SIZE;SMNT;STAT;STOR;STOU;STRU;SYST;TYPE;USER;XCUP;XMKD;XPWD;XRCP;XRMD;XRSQ;XSEM;XSEN"},
        {"Type": "upload", "DataCheck": case1_upload},
        {"Type": "download", "DataCheck": case1_downfile}
    ]}
}

delftpcheck = {'DropFtpCheck': {
    "MethodName": "DropFtpCheck",
    "MessageTime": datatime,
    "Sender": "Centre0",
    "Content": []
}}
