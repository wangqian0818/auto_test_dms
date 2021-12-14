# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port
http_url = 'http://' + proxy_ip + ':' + str(http_proxy_port)

# http相关参数设置
get1_data1 = 'hello'
get1_data2 = 'juson'
case1_get_data1 = {'data': get1_data1}
case1_get_data2 = {'data': get1_data2}
post1_data1 = '123'
post1_data2 = '456'
case1_post_data1 = {'data': post1_data1}
case1_post_data2 = {'data': post1_data2}
check1_uri1 = 'mzh'
check1_uri2 = 'hkl'
case1_uri1 = http_url + '/' + check1_uri1
case1_uri2 = http_url + '/' + check1_uri2
file_name = 'test.'
MIME1_uri1 = 'css'
MIME1_uri2 = 'avi'
uri = 'pdf'
case1_MIME1 = http_url + '/' + file_name + MIME1_uri1
case1_MIME2 = http_url + '/' + file_name + MIME1_uri2
base_uri = http_url + '/' + file_name + uri

# 当有过滤内容时，data内容必须是键值对
data = {'data': 'abc'}
http_ip = proxy_ip + ':' + str(http_proxy_port)
# 配置下发
# 列表里面的顺序依次为：查询命令，预期结果
case1_step1 = {
    "step1": ["cat /etc/jsac/http.stream", http_ip]
}
case1_step11 = {
    "step1": ["netstat -anp |grep tcp", http_ip]
}
case1_step2 = {
    "step1": ["cat /etc/jsac/http.json", "c_get_args"],
    "step2": ["cat /etc/jsac/http.json", get1_data1],
    "step3": ["cat /etc/jsac/http.json", get1_data2],
    "step4": ["cat /etc/jsac/http.json", "c_post_args"],
    "step5": ["cat /etc/jsac/http.json", post1_data1],
    "step6": ["cat /etc/jsac/http.json", post1_data2],
    "step7": ["cat /etc/jsac/http.json", "c_http_uri"],
    "step8": ["cat /etc/jsac/http.json", check1_uri1],
    "step9": ["cat /etc/jsac/http.json", check1_uri2],
    "step10": ["cat /etc/jsac/http.json", "s_content_type"],
    "step11": ["cat /etc/jsac/http.json", MIME1_uri1],
    "step12": ["cat /etc/jsac/http.json", MIME1_uri2],
    "step13": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", get1_data1],
    "step14": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", get1_data2],
    "step15": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", post1_data1],
    "step16": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", post1_data2],
    "step17": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", check1_uri1],
    "step18": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", check1_uri2],
    "step19": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", MIME1_uri1],
    "step20": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", MIME1_uri2]
}

case2_step2 = {
    "step1": ["cat /etc/jsac/http.json", "c_get_args"],
    "step2": ["cat /etc/jsac/http.json", get1_data1],
    "step3": ["cat /etc/jsac/http.json", get1_data2],
    "step4": ["cat /etc/jsac/http.json", "c_post_args"],
    "step5": ["cat /etc/jsac/http.json", post1_data1],
    "step6": ["cat /etc/jsac/http.json", post1_data2],
    "step7": ["cat /etc/jsac/http.json", "c_http_uri"],
    "step8": ["cat /etc/jsac/http.json", check1_uri1],
    "step9": ["cat /etc/jsac/http.json", check1_uri2],
    "step10": ["cat /etc/jsac/http.json", "s_content_type"],
    "step11": ["cat /etc/jsac/http.json", MIME1_uri1],
    "step12": ["cat /etc/jsac/http.json", MIME1_uri2],
    "step13": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", get1_data1],
    "step14": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", get1_data2],
    "step15": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", post1_data1],
    "step16": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", post1_data2],
    "step17": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", check1_uri1],
    "step18": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", check1_uri2],
    "step19": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", MIME1_uri1],
    "step20": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", MIME1_uri2]
}

delcheck = {
    "step1": ["cat /etc/jsac/http.json", "http"]
}
