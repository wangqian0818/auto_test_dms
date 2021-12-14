# coding:utf-8
from common import baseinfo

url = baseinfo.http_proxy_url

# http相关参数设置
"""
用例一：MIME白名单,URI和parameter黑名单
    "AppRules":  [{
        "Action":  "deny",
        "RuleId":  27,
        "Method":  ["GET","POST"],
        "Parameter":  ["wq","juson"],
        "URI":  ["mzh", "456"]
      }, {
        "Action":  "allow",
        "RuleId":  18,
        "Method":  ["GET","POST"],
        "MIME":  ["css", "avi"]
      }]
"""
'''
用例二：MIME,URI和parameter黑名单

"Action":  "Deny",
"Method":  ["GET", "POST"],
"Parameter":  ["pdf", "js"],
"MIME":  ["css", "avi"],
"URI":  ["mzh", "456"]
'''

ruleid = 233
check1_method = ["GET", "POST"]
check1_uri = ["mzh", "456"]
check1_parameter = ["pdf", "js"]
check1_MIME = ["css", "avi"]

# /mzh.pdf
case1_url1 = url + '/' + check1_uri[0] + '.' + check1_parameter[0]
# /mzh.js
case1_url2 = url + '/' + check1_uri[0] + '.' + check1_parameter[1]
# /456.pdf
case1_url3 = url + '/' + check1_uri[0] + '.' + check1_parameter[0]
# /456.js
case1_url4 = url + '/' + check1_uri[1] + '.' + check1_parameter[1]

# 用例一中，以白名单结尾的url，不满足黑名单的交集，所以不阻拦
# /mzh.css
case1_url5 = url + '/' + check1_uri[0] + '.' + check1_MIME[0]
# /mzh.avi
case1_url6 = url + '/' + check1_uri[1] + '.' + check1_MIME[1]
# /456.css
case1_url7 = url + '/' + check1_uri[0] + '.' + check1_MIME[0]
# /456.avi
case1_url8 = url + '/' + check1_uri[1] + '.' + check1_MIME[1]



