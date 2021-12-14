# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
upremotePath = baseinfo.ftp_upremotePath
uplocalPath = baseinfo.ftp_uplocalPath
downremotePath = baseinfo.ftp_downremotePath
downlocalPath = baseinfo.ftp_downlocalPath
host = baseinfo.gwClientIp
port = baseinfo.ftp_proxy_port
username = baseinfo.ftp_user
password = baseinfo.ftp_pass

# ftp相关参数设置


'''
用例一：无上传、下载、删除的FTP传输策略
        "Action":  "Allow",
        "Cmd":  ["ABOR", "ACCT", "ADAT", "ALLO", "APPE", "AUTH", "CCC", "CDUP", "CONF", "CWD", "DELE", "ENC", "EPRT",
         "EPSV", "FEAT", "HELP", "LANG", "LIST", "LPRT", "LPSV", "MDTM", "MIC", "MKD", "MLSD", "MLST", "MODE", "NLST",
          "NOOP", "OPTS", "PASS", "PASV", "PBSZ", "PORT", "PROT", "PWD", "QUIT", "REIN", "REST", "STOR", "RMD", "RNFR"
          , "RNTO", "SITE", "SIZE", "SMNT", "STAT", "STOU", "STRU", "SYST", "TYPE", "USER", "XCUP", "XMKD", "XPWD",
           "XRCP", "XRMD", "XRSQ", "XSEM", "XSEN"]
'''

'''
用例二：白名单cmd列表中无下载的FTP传输策略
        "Action":  "Allow",
        "Cmd":  ["ABOR", "ACCT", "ADAT", "ALLO", "APPE", "AUTH", "CCC", "CDUP", "CONF", "CWD", "ENC", "EPRT", "EPSV",
         "FEAT", "HELP", "LANG", "LIST", "LPRT", "LPSV", "MDTM", "MIC", "MKD", "MLSD", "MLST", "MODE", "NLST", "NOOP"
         , "OPTS", "PASS", "PASV", "PBSZ", "PORT", "PROT", "PWD", "QUIT", "REIN", "REST", "RMD", "RNFR", "RNTO", 
         "SITE", "SIZE", "SMNT", "STAT", "STOU", "STRU", "SYST", "TYPE", "USER", "XCUP", "XMKD", "XPWD", "XRCP", 
         "XRMD", "XRSQ", "XSEM", "XSEN"]
'''
action = 'allow'
upload_filename = '1.'
upload = 'txt'
upload_file = upload_filename + upload
upremotePath = upremotePath + upload_file
uplocalPath = uplocalPath + upload_file

down_filename = '456.'
downfile = 'txt'
down_file = down_filename + downfile
downremotePath = downremotePath + down_file
downlocalPath = downlocalPath + down_file
