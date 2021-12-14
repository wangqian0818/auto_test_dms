# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port
http_url = 'http://' + proxy_ip + ':' + str(http_proxy_port)

# http相关参数设置
# post的下载只能是放在uri的后缀curl http://10.10.88.9:2286/1.pdf -v，且只能是get请求
file_name = 'test.'
uri = 'doc'
base_uri = http_url + '/' + file_name + uri
check1_uri = 'pdf'
case1_uri = http_url + '/' + file_name + check1_uri

application_uri = 'js'
audio_uri = 'mps'
image_uri = 'gif'
text_uri = 'tsv'
video_uri = 'avi'
case2_uri1 = http_url + '/' + file_name + application_uri
case2_uri2 = http_url + '/' + file_name + audio_uri
case2_uri3 = http_url + '/' + file_name + image_uri
case2_uri4 = http_url + '/' + file_name + text_uri
case2_uri5 = http_url + '/' + file_name + video_uri

# 当有过滤内容时，get内容必须是键值对
data = {'data': 'abc'}
MIME_all = '"evy", "fif", "spl", "hta", "acx", "hqx", "doc", "dot", "*", "bin", "class", "dms", "exe", "lha", "lzh", "oda", "axs", "pdf", "prf", "p10", "crl", "ai", "eps", "ps", "rtf", "setpay", "setreg", "xla", "xlc", "xlm", "xls", "xlt", "xlw", "msg", "sst", "cat", "stl", "pot", "pps", "ppt", "mpp", "wcm", "wdb", "wks", "wps", "hlp", "bcpio", "cdf", "application/x-compress", "z", "cpio", "csh", "dcr", "dir", "dxr", "dvi", "gtar", "gz", "hdf", "ins", "isp", "iii", "js", "latex", "mdb", "crd", "clp", "dll", "m13", "m14", "mvb", "wmf", "mny", "pub", "scd", "trm", "wri", "cdf", "nc", "pma", "pmc", "pml", "pmr", "pmw", "p12", "pfx", "p7b", "spc", "p7r", "p7c", "p7m", "p7s", "sh", "shar", "swf", "sit", "sv4cpio", "sv4crc", "tar", "tcl", "tex", "texi", "texinfo", "roff", "t", "tr", "man", "me", "ms", "ustar", "src", "cer", "crt", "der", "pko", "zip", "au", "snd", "mid", "rmi", "mps", "aif", "aifc", "aiff", "m3u", "ra", "ram", "wav", "bmp", "cod", "gif", "ief", "jpe", "jpeg", "jpg", "jfif", "svg", "tif", "tiff", "ras", "cmx", "ico", "pnm", "pbm", "pgm", "ppm", "rgb", "xbm", "xpm", "xwd", "mht", "mhtml", "mws", "css", "323", "htm", "html", "stm", "uls", "bas", "c", "h", "txt", "rtx", "sct", "tsv", "htt", "htc", "etx", "vcf", "mp2", "mpa", "mpe", "mpeg", "mpg", "mpv2", "mov", "qt", "lsf", "lsx", "asf", "asr", "asx", "avi", "movie", "flr", "vrml", "wrl", "wrz", "xaf", "xof"'
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
    "step1": ["cat /etc/jsac/http.json", "s_content_type"],
    "step2": ["cat /etc/jsac/http.json", check1_uri],
    "step3": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", check1_uri]
}

case2_step2 = {
    "step1": ["cat /etc/jsac/http.json", "s_content_type"],
    "step2": ["cat /etc/jsac/http.json", application_uri],
    "step3": ["cat /etc/jsac/http.json", audio_uri],
    "step4": ["cat /etc/jsac/http.json", image_uri],
    "step5": ["cat /etc/jsac/http.json", text_uri],
    "step6": ["cat /etc/jsac/http.json", video_uri],
    "step7": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", application_uri],
    "step8": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", audio_uri],
    "step9": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", image_uri],
    "step10": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", text_uri],
    "step11": [r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", video_uri]
}

case3_step2 = {
    "step1": ["cat /etc/jsac/http.json", "s_content_type"],
    "step2": ["cat /etc/jsac/http.json", MIME_all]
}

delcheck = {
    "step1": ["cat /etc/jsac/http.json", "http"]
}
