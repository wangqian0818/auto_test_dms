# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.gwClientIp
http_proxy_url = baseinfo.http_proxy_url

smtp_proxy_port = baseinfo.smtp_proxy_port
pop3_proxy_port = baseinfo.pop3_server_port
mail_attach = baseinfo.mail_attach
downlocalPath = baseinfo.mail_attach

'''
用例一：smtp模块关键字为，juson【title】，tech【content】，1203【附件文件名】，卓讯【附件内容】
       pop3模块关键字为，科技【附件内容】
[{
    "AppId":  3,
    "AppRules":  [{
        "Pattern":  "anVzb24=",
        "RuleId":  101,
        "SPattern":  "juson",
        "Flags":  "FLAG_CASELESS"
      }, {
        "Pattern":  "dGVjaA==",
        "RuleId":  102,
        "SPattern":  "tech",
        "Flags":  "FLAG_CASELESS"
      }, {
        "Pattern":  "5Y2T6K6v",
        "RuleId":  103,
        "SPattern":  "卓讯",
        "Flags":  "FLAG_CASELESS"
      }, {
        "Pattern":  "1203",
        "RuleId":  104,
        "Flags":  "FLAG_CASELESS"
      }]
  }, {
    "AppId":  4,
    "AppRules":  [{
        "Pattern":  "56eR5oqA",
        "RuleId":  101,
        "SPattern":  "科技",
        "Flags":  "FLAG_CASELESS"
      }]
  }]
'''

# smtp相关参数设置
deny_mail = 'jusontest@163.com'
deny_pwd = 'UMXDELUQAPUWQFNU'

# pop3相关参数设置
# 获取邮箱密码和对应邮箱POP3服务器,邮件地址跟收件人相同
mail_ruleid = '101;102;103;104'
title_juson = '关于用例——tcp_keyword_juson'
context_tech = '测试内容-content_tech'
title = '关于用例——tcp_keyword'
context = '测试内容-content'
file_juson = 'mail_file_1203.txt'  # 文件内容为卓讯
file_tech = 'mail_file.txt'  # 文件内容为科技
juson_file_path = mail_attach + file_juson
tech_file_path = mail_attach + file_tech
filename_keyword = '1203'
juson_keyword = 'juson'
tech_keyword = 'tech'
smtp_keyword = '卓讯'
pop3_keyword = '科技'
juson_base64 = 'anVzb24='
tech_base64 = 'dGVjaA=='
smtp_keyword_base64 = '5Y2T6K6v'
pop3_keyword_base64 = '56eR5oqA'

'''
用例二：FTP关键字过滤，禁止上传命令，禁止文件内容或者文件名包含wq的内容
    "AppRules":  [{
        "Pattern":  "wq",
        "RuleId":  1,
        "Flags":  "FLAG_CASELESS"
      }, {
        "Pattern":  "STOR",
        "RuleId":  2,
        "Flags":  "FLAG_CASELESS"
      }]

'''
# ftp相关参数设置
ftp_ruleid = '110;111'
filename = 'test.'
case2_downfile = 'txt'
case2_file = filename + case2_downfile
ftp_upremotePath = baseinfo.ftp_upremotePath
ftp_uplocalPath = baseinfo.ftp_uplocalPath
downremotePath = baseinfo.ftp_downremotePath
case2_upremotePath = ftp_upremotePath + case2_file
case2_uplocalPath = ftp_uplocalPath + case2_file
case2_downremotePath = downremotePath + case2_file
case2_downlocalPath = downlocalPath + case2_file
ftp_keyword1 = 'wq'
ftp_keyword2 = 'STOR'

'''
用例三：tcp 关键字过滤，禁止post请求，禁止文件内容或者文件名包含123的内容
    "AppRules":  [{
        "Pattern":  "123",
        "RuleId":  105,
        "Flags":  "FLAG_CASELESS"
      }, {
        "Pattern":  "post",
        "RuleId":  106,
        "Flags":  "FLAG_CASELESS"
      }]
'''
tcp_ruleid = '121;122'
tcp_keyword1 = '123'
tcp_keyword2 = 'post'
allow_file = '2.txt'
deny_file = tcp_keyword1 + '.txt'
allow_url = http_proxy_url + '/' + allow_file
deny_url = http_proxy_url + '/' + deny_file
