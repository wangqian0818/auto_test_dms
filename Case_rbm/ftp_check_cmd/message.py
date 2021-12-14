import time

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
proxy_ip = baseinfo.gwClientIp
ftp_ip = baseinfo.ftp_ip
server_ip = baseinfo.http_server_ip
server_port = baseinfo.http_server_port
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
    "Content": [
        {"Type": "cmd",
         "DataCheck": "ABOR;ACCT;ADAT;ALLO;APPE;AUTH;CCC;CDUP;CONF;CWD;ENC;EPRT;EPSV;FEAT;HELP;LANG;LIST;LPRT;LPSV;MDTM;MIC;MKD;MLSD;MLST;MODE;NLST;NOOP;OPTS;PASS;PASV;PBSZ;PORT;PROT;PWD;QUIT;REIN;REST;RMD;RNFR;RNTO;SITE;SIZE;SMNT;STAT;STOU;STRU;SYST;TYPE;USER;XCUP;XMKD;XPWD;XRCP;XRMD;XRSQ;XSEM;XSEN"}
    ]}
}

ftpcheck2 = {'SetFtpCheck': {
    "MethodName": "SetFtpCheck",
    "MessageTime": datatime,
    "Sender": "Centre0",
    "Content": [
        {"Type": "cmd",
         "DataCheck": "ABOR;ACCT;ADAT;ALLO;APPE;AUTH;CCC;CDUP;CONF;CWD;DELE;ENC;EPRT;EPSV;FEAT;HELP;LANG;LIST;LPRT;LPSV;MDTM;MIC;MKD;MLSD;MLST;MODE;NLST;NOOP;OPTS;PASS;PASV;PBSZ;PORT;PROT;PWD;QUIT;REIN;REST;RETR;RMD;RNFR;RNTO;SITE;SIZE;SMNT;STAT;STOU;STRU;SYST;TYPE;USER;XCUP;XMKD;XPWD;XRCP;XRMD;XRSQ;XSEM;XSEN"}
    ]}
}

delftpcheck = {'DropFtpCheck': {
    "MethodName": "DropFtpCheck",
    "MessageTime": datatime,
    "Sender": "Centre0",
    "Content": []
}}
