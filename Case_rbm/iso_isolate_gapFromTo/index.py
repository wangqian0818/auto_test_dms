# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port

http_ip1 = proxy_ip + ':' + str(http_proxy_port)
http_url1 = 'http://' + http_ip1

front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameInside

case1_gapFromTo = {
    "GapFromTo": {}  # 出接口；非必选
}

case2_gapFromTo = {
        "FromTo": "BA",  # 通信方向，AB与BA之间选一个；
        "Input": front_ifname,  # 入接口；非必选
        "Output": back_ifname  # 出接口；非必选
}

case3_gapFromTo = {
        "FromTo": "AB",  # 通信方向，AB与BA之间选一个；
        "Input": front_ifname,  # 入接口；非必选
        "Output": back_ifname  # 出接口；非必选
}



