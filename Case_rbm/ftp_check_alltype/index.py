# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.gwClientIp
upremotePath = baseinfo.ftp_delePath  # 上传一个文件到ftp的del文件夹下，保证cmd用例可以正常删除
uplocalPath = baseinfo.ftp_uplocalPath
downremotePath = baseinfo.ftp_downremotePath
downlocalPath = baseinfo.ftp_downlocalPath

# ftp相关参数设置
host = baseinfo.gwClientIp
port = baseinfo.ftp_proxy_port
deny_user = 'lwq'

"""
用例一：user和cmd白名单[没有dele命令，禁止删除文件]，upload后缀名黑名单
[{
    "AppId":  5,
    "AppRules":  [{
        "RuleId":  106,
        "Action":  "Allow",
        "User":  ["test"],
        "Cmd":  ["ABOR;ACCT;ADAT;ALLO;APPE;AUTH;CCC;CDUP;CONF;CWD;DELE;ENC;EPRT;EPSV;FEAT;HELP;LANG;LIST;LPRT;LPSV;
        MDTM;MIC;MKD;MLSD;MLST;MODE;NLST;NOOP;OPTS;PASS;PASV;PBSZ;PORT;PROT;PWD;QUIT;REIN;REST;RMD;RNFR;RNTO;SITE;
        SIZE;SMNT;STAT;STOR;STOU;STRU;SYST;TYPE;USER;XCUP;XMKD;XPWD;XRCP;XRMD;XRSQ;XSEM;XSEN;RMD;STOR;RETR"]
      }, {
        "RuleId":  107,
        "Action":  "Deny",
        "UploadExt":  ["pdf"]
      }]
  }]
"""

"""
用例二：user和cmd白名单[没有dele命令，禁止删除文件]，download后缀名黑名单
[{
    "AppId":  5,
    "AppRules":  [{
        "RuleId":  106,
        "Action":  "Allow",
        "User":  ["test"],
        "Cmd":  ["ABOR;ACCT;ADAT;ALLO;APPE;AUTH;CCC;CDUP;CONF;CWD;DELE;ENC;EPRT;EPSV;FEAT;HELP;LANG;LIST;LPRT;LPSV;
        MDTM;MIC;MKD;MLSD;MLST;MODE;NLST;NOOP;OPTS;PASS;PASV;PBSZ;PORT;PROT;PWD;QUIT;REIN;REST;RMD;RNFR;RNTO;SITE;
        SIZE;SMNT;STAT;STOR;STOU;STRU;SYST;TYPE;USER;XCUP;XMKD;XPWD;XRCP;XRMD;XRSQ;XSEM;XSEN;RMD;STOR;RETR"]
      }, {
        "RuleId":  107,
        "Action":  "Deny",
        "DownloadExt":  ["pdf"]
      }]
  }]
"""

allow_action = 'allow'
deny_action = 'deny'
check_allow = 'txt'
check_deny = 'pdf'
upload_filename = '1.'
case_upload_file = upload_filename + check_allow
case_upload_deny_file = upload_filename + check_deny
case_upremotePath = upremotePath + '/' + case_upload_file
case_uplocalPath = uplocalPath + case_upload_file
case_deny_upremotePath = upremotePath + '/' + case_upload_deny_file
case_deny_uplocalPath = uplocalPath + case_upload_deny_file

down_filename = '456.'
case_down_file = down_filename + check_allow
case_down_deny_file = down_filename + check_deny
case_downremotePath = downremotePath + case_down_file
case_downlocalPath = downlocalPath + case_down_file
case_deny_downremotePath = downremotePath + case_down_deny_file
case_deny_downlocalPath = downlocalPath + case_down_deny_file
