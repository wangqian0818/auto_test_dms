# coding: utf-8

import time

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
proxy_ip = baseinfo.gwClientIp
http_proxy_port = baseinfo.http_proxy_port
http_server_ip = baseinfo.http_server_ip
http_server_port = baseinfo.http_server_port

front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameInside
windows_sip = baseinfo.windows_sip
front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid
http_server = baseinfo.http_server_ip
http_server_port_file = baseinfo.http_server_port_file

ftp_ip = baseinfo.ftp_ip
ftp_proxy_port = baseinfo.ftp_proxy_port

smtp_ip = baseinfo.smtp_ip
pop3_ip = baseinfo.pop3_ip
smtp_proxy_port = baseinfo.smtp_proxy_port
pop3_proxy_port = baseinfo.pop3_proxy_port
check_data = None

cardid0 = baseinfo.gwCard0
pcap_dip = baseinfo.serverOpeIp
pcap_sip = baseinfo.clientOpeIp
Ifname = baseinfo.pcapReadIface

# appid
http_appid = baseinfo.http_appid
tcp_appid = baseinfo.tcp_appid
tcp_ssh_appid = baseinfo.tcp_ssh_appid
smtp_appid = baseinfo.smtp_appid
pop3_appid = baseinfo.pop3_appid
ftp_appid = baseinfo.ftp_appid
app_appid = baseinfo.app_appid
# 新管控新增了ruleid
http_ruleid = baseinfo.http_ruleid
http_post_ruleid = baseinfo.http_post_ruleid
tcp_ruleid = baseinfo.tcp_ruleid
tcp_ssh_ruleid = baseinfo.tcp_ssh_ruleid
smtp_ruleid = baseinfo.smtp_ruleid
pop3_ruleid = baseinfo.pop3_ruleid
ftp_ruleid = baseinfo.ftp_ruleid
app_ruleid = baseinfo.app_ruleid

# cipso标记相关
cipso_appid = baseinfo.cipso_appid

# 新管控新增代理_接口
agent = {
    'agent': {
        "MethodName": "SetAccessConf",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "AppId": 123,  # 业务id，策略主键，不可修改
            "L4protocol": "tcp",  # 4层协议，tcp和udp之间选一个
            "Module": "ftp",  # 应用层协议，ftp，smtp，pop3和http之间选一个
            "Sip": "10.10.100.123",  # 源地址
            "Dip": "10.10.88.123",  # 目的地址
            "Dport": 9090,  # 目的端口
            "Lip": "10.10.100.11",  # 代理地址
            "Lport": 9090,  # 代理端口
            "Mode": 2,  # 业务模式，0（路由），1（透明代理），2（反向代理）之间选一个
            "GapFromTo": {  # 隔离设备下必选
                "FromTo": "AB",  # 通信方向，AB与BA之间选一个；
                "Input": "bond1",  # 入接口；非必选
                "Output": "enp59s0f00"}  # 出接口；非必选
        }]
    }
}
del_agent = {
    'agent': {
        "MethodName": "DelAccessConf",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "AppIds": [http_appid]
        }]
    }
}
# 新管控，增删数据结构检查策略
SetDataCheck = {
    'SetDataCheck': {
        "Sender": "Centre0",
        "MessageTime": datatime,
        "MethodName": "SetHttpCheck",
        "Content":
            [{'AppId': http_appid,  # 业务id
              'AppRules': [
                  {'RuleId': http_ruleid,  # 策略id，策略主键，不可修改
                   'Action': 'Deny'  # 策略命中后的执行动作，Allow或Deny
                   # http
                   # 'Method': ['GET', 'POST'],  # 方法过滤
                   # 'Parameter': ['html', 'xml'],  # 参数过滤
                   # 'MIME': ['text/plain', 'image/gif'],  # MIME过滤
                   # 'URI': ['/ditu', '/jimi']  # URI过滤

                   # ftp
                   # 'User':['name1','name2','name3'],# 用户过滤
                   # 'Cmd':['DELE','RMD','STOR','RETR'],# 命令过滤   [删除文件，删除文件夹，上传，下载]
                   # 'UploadExt':['txt','doc','exe'],# 上传文件扩展名过滤
                   # 'DownloadExt':['txt','doc','exe']# 下载文件扩展名过滤

                   # mail
                   # 'FromTo':['zq@qq.com','zq1@qq.com'],# 邮件地址过滤
                   # 'Subject':['xxxx','aaaaaa'],# 主题关键字过滤
                   # 'AttachmentExt':['txt','doc','exe']# 附件扩展名过滤
                   }]
              }]
    }
}
DelCheck = {
    'DelCheck': {
        "Sender": "Centre0",
        "MessageTime": datatime,
        "MethodName": "DelHttpCheck",
        "Content": [{
            'AppId': 123,  # 业务id
            'RuleIds': [22, 23]  # 策略id
        }]
    }
}

# 安全标记策略-设置安全标记策略
SetSelabel = {
    'SetSelabel': {
        "Sender": "Centre0",
        "MessageTime": datatime,
        "MethodName": "SetSelabel",
        "Content": [{
            'AppId': cipso_appid,  # 业务id
            # 'MtLabel': {   # 正向比对的标记
            #     'DOI': 12,  # Doi
            #     'Type': 1,  # 解释域，整形，取值1~UINT32_MAX
            #     'Match': 0,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
            #     'Sensitivity': '1-100',  # 机密性级别比较范围
            #     'Integrity': '1-100',  # 完整性级别比较范围
            #     'Cat': '0xff,0xff,0xff,0xff',  # 类别列表比较对象
            # },
            # 'TgLabel': {  # 正向出口标记，标记动作为转换时候必须配置TgLabel
            #     'DOI': 12,  # Doi
            #     'Type': 1,  # 解释域，整形，取值1~UINT32_MAX
            #     'Match': 0,  # 位图比较方式，0（子集），1（交集），2（重合），3（不相交）之间选一个
            #     'Sensitivity': '1-100',  # 机密性级别比较范围
            #     'Integrity': '1-100',  # 完整性级别比较范围
            #     'Cat': '0xff,0xff,0xff,0xff',  # 类别列表比较对象
            # },
            # 'RvMtLabel': {  # # 配置参考MtLabel；可不配置
            #     'DOI': 12,
            #     'Type': 1,
            #     'Match': 0,
            #     'Sensitivity': '1-100',
            #     'Integrity': '1-100',
            #     'Cat': '0xff,0xff,0xff,0xff',
            # },
            # 'RvTgLabel': [{  # # 配置参考MtLabel；可不配置
            #     'DOI': 12,
            #     'Type': 1,
            #     'Match': 0,
            #     'Sensitivity': '1-100',
            #     'Integrity': '1-100',
            #     'Cat': '0xff,0xff,0xff,0xff',
            # },
        }]
    }
}

# 安全标记策略-删除安全标记策略
DelSelabel = {
    'DelSelabel': {
        "Sender": "Centre0",
        "MessageTime": datatime,
        "MethodName": "DelSelabel",
        "Content": [{
            'AppId': cipso_appid,  # 业务id
        }]
    }
}

# ACL-设置网络安全策略
SetAcl = {
    'SetAcl': {
        "Sender": "Centre0",
        "MessageTime": datatime,
        "MethodName": "SetAcl",
        "Content": [{
            'AppId': app_appid,  # 业务id
            'Ifname': 'enp60s0f00',  # 具体接口，若策略不指定接口，则无此字段
            'Location': 'B',  # 隔离类型设备需要区分AB机，填充A（主机A）B（主机B）中的一个；网关类型设备没有此字段
            'Sip': '10.10.100.17',  # 源地址，支持添加掩码，例如：'10.10.100.0/24'
            'Sport': '3846',  # 源端口，支持端口段，例如：'2000-3000'
            'Dip': '10.10.100.32',  # 目的地址，支持添加掩码，例如：'10.10.100.0/24'
            'Dport': '8080',  # 目的端口，支持端口段，例如：'2000-3000'
            'Protocol': '6',  # 协议号，支持TCP，UDP和协议号数值
            'Listorder': 10,  # 优先级
            'Action': 0,  # 动作，0转发，1丢弃
        }]
    }
}

# ACL-删除网络安全策略
DelAcl = {
    'DelAcl': {
        "Sender": "Centre0",
        "MessageTime": datatime,
        "MethodName": "DelAcl",
        "Content": [{
            'AppId': app_appid,  # 业务id
            'RuleIds': [],
        }]
    }
}

# 内容审查策略配置-内容审查策略配置
SetKeywordScan = {
    'SetKeywordScan': {
        "Sender": "Centre0",
        "MessageTime": datatime,
        "MethodName": "SetKeywordScan",
        "Content": [{
            "AppId": 1,
            "AppRules": [
                #     {
                #     "SPattern": "转码前内容",  # 若关键词转码，则Spattern为转码前内容；不转码则无
                #     "Pattern": "wq",  # 关键词内容，或者正则表达式
                #     "RuleId": 1,  # 策略id，策略主键
                #     "Flags": "FLAG_CASELESS"  # 匹配参数，有固定值可选；多个之间分号间隔
                # }
            ]  # FLAG_CASELESS：设置不区分大小写的匹配。
        }],
    }
}

# 定制应用策略配置
SetUDACheck = {
    'SetUDACheck': {
        "Sender": "Centre0",
        "MessageTime": datatime,
        "MethodName": "SetUDACheck",
        "Content": [{
            "AppId": 123,  # 业务id
            "AppRules": [
                {"RuleId": 22,  # 策略id，策略主键，不可修改
                 "Action": "allow",  # 执行动作，allow和deny之间选一个
                 "Direction": "upstream",  # 匹配方向，downstream，upstream和twoway之间选一个
                 "Cmds": [  # list形式
                     {"cmd": "From",  # 命令字
                      "para": "QingDao",  # 命令字参数
                      "offset": 0,  # 命令字相对偏移量
                      "delimiter": ":",  # 命令字与参数之间分割符
                      "end": "\r\n",  # 参数结束符
                      "rcode": "OK",  # 命令字关联的响应字段；当匹配方向为twoaway时可配，其他情况不可配
                      "roffset": 0}  # 关联的响应字段偏移；
                 ],
                 "Cmpns": [  # list形式
                     {"value": "0x12345",  # 被比较的值
                      "operation": "=",  # 比较操作，<，>和=之间选一个
                      "offset": 0,  # 被比较值的偏移量
                      "nnn": 2,  # 字节数模式，1,2,4和8之间选一个；字段表示报文内容为一个数值
                      "end": "\r\n",  # 结束字符串模式，字段表示报文内容为一个字符串
                      "rvalue": "8000",  # 数值关联的响应字段；当匹配方向为twoaway时可配，其他情况不可配
                      "roperation": "=",  # 关联响应的比较操作
                      "roffset": 0,  # 关联响应的偏移量
                      "rnnn": 2,  # 关联响应的字符数
                      "rend": "\r\n"}  # 关联响应的结束字符串
                 ]
                 }
            ]
        }
        ]
    }
}
