#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/10/20 16:45
import logging
import sys

import common.baseinfo as baseinfo
# 公共调用接口函数，所需属性值
from common import all_interface

log = logging.getLogger(__name__)
# proxy_ip = baseinfo.gwInternetIp  # 10.10.101.47
proxy_ip = baseinfo.gwClientIp  # "192.168.30.47"
clientOpeIp = baseinfo.clientOpeIp  # "192.168.30.148"
serverOpeIp = baseinfo.serverOpeIp  # "192.168.50.149"
gwCard0 = baseinfo.gwCard0
pcapReadIface = baseinfo.pcapReadIface

http_server_ip = baseinfo.http_server_ip
http_server_port = baseinfo.http_server_port
http_proxy_port = baseinfo.http_proxy_port

ftp_ip = baseinfo.ftp_ip
ftp_proxy_port = baseinfo.ftp_proxy_port

smtp_ip = baseinfo.smtp_ip
pop3_ip = baseinfo.pop3_ip

smtp_server_port = baseinfo.smtp_server_port
smtp_proxy_port = baseinfo.smtp_proxy_port
pop3_server_port = baseinfo.pop3_server_port
pop3_proxy_port = baseinfo.pop3_proxy_port

# 隔离模块
# 公共模块
windows_sip = baseinfo.windows_sip
BG8010FrontOpeIp = baseinfo.BG8010FrontOpeIp  # 前置机业务ip
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameInside
front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid
src_domain = 'src'
dest_domain = 'dest'

# http模块
http_server_port_file = baseinfo.http_server_port_file
http_redirect_ip = baseinfo.http_redirect_ip
http_redirect_port = baseinfo.http_redirect_port
http_appid = baseinfo.http_appid
http_post_appid = baseinfo.http_post_appid
http_module = 'http'

# tcp模块
tcp_appid = baseinfo.tcp_appid
tcp_ssh_appid = baseinfo.tcp_ssh_appid
iso_timeout = baseinfo.iso_timeout
BG8010ServerOpeIp = baseinfo.BG8010ServerOpeIp
BG8010ClientOpeIp = baseinfo.BG8010ClientOpeIp
ssh_proxy_port = baseinfo.ssh_proxy_port

# udp模块
udp_appid = baseinfo.udp_appid
dns_port = baseinfo.dns_port
dns_proxy_port = baseinfo.dns_proxy_port

# mail模块
smtp_appid = baseinfo.smtp_appid
smtp_module = 'smtp'
pop3_appid = baseinfo.pop3_appid
pop3_module = 'pop3'

# ftp模块
ftp_appid = baseinfo.ftp_appid
ftp_dport = baseinfo.ftp_dport
ftp_module = 'ftp'

# customapp模块
app_appid = baseinfo.app_appid
app_proxy_port = baseinfo.app_proxy_port
ssh_dport = baseinfo.ssh_dport
value_5 = '"' + '0x32303020' + '"'
value_6 = '"' + '540028978' + '"'

# 关键字过滤
smtp_keyword = "cGF0dGVybj0iNVkyVDZLNnYiIGZsYWdzPSJGTEFHX0NBU0VMRVNTIg0K"  # 卓讯的base64编码的file
pop3_keyword = "cGF0dGVybj0iNTZlUjVvcUEiIGZsYWdzPSJGTEFHX0NBU0VMRVNTIg0K"  # 科技的base64编码的file
ftp_keyword = 'cGF0dGVybj0iUkVUUiIgZmxhZ3M9IkZMQUdfQ0FTRUxFU1MiDQo='  # RETR的file
http_keyword = 'cGF0dGVybj0iZ2V0IiBmbGFncz0iRkxBR19DQVNFTEVTUyINCg=='  # get的file

# 新管控新增了ruleid
http_ruleid = baseinfo.http_ruleid
http_post_ruleid = baseinfo.http_post_ruleid
tcp_ruleid = baseinfo.tcp_ruleid
tcp_ssh_ruleid = baseinfo.tcp_ssh_ruleid
smtp_ruleid = baseinfo.smtp_ruleid
pop3_ruleid = baseinfo.pop3_ruleid
ftp_ruleid = baseinfo.ftp_ruleid
app_ruleid = baseinfo.app_ruleid

# cipso相关参数设置
cipso_appid = baseinfo.cipso_appid


class interface():

    def __init__(self):

        # 网关的代理下发接口，content
        self.content_dict = {
            "Lip": proxy_ip,
            "AppId": http_appid,
            "Dport": http_server_port,
            "Mode": 2,  # 反向代理
            "Dip": http_server_ip,
            "Sip": "192.168.30.148",
            "Module": http_module,
            "L4protocol": "tcp",
            "Lport": http_proxy_port,  # 设备端代理端口
            "GapFromTo": {  # 隔离设备下必选，网关设备需要移除该属性
                "FromTo": "AB",  # 通信方向，AB与BA之间选一个；
                "Input": front_ifname,  # 入接口；非必选
                "Output": back_ifname}  # 出接口；非必选
        }
        # 数据结构检查接口，content
        self.data_check_dict = {
            'AppId': http_appid,  # 业务id
            'AppRules': [
                {'RuleId': http_ruleid,
                 "Action": "deny"}
            ]
        }
        # 关键字过滤策略，content
        self.keyword_content_dict = {
            "AppId": 1,
            "AppRules": [
                {
                    # "SPattern": "转码前内容",  # 若关键词转码，则Spattern为转码前内容；不转码则无
                    "Pattern": "wq",  # 关键词内容，或者正则表达式
                    "RuleId": 1,  # 策略id，策略主键
                    "Flags": "FLAG_CASELESS"  # 匹配参数，有固定值可选；多个之间分号间隔
                }]
        }
        # 标记下发接口，content
        self.cipso_content_dict = {
            'AppId': app_appid,  # 业务id
        }

        # acl下发接口，content
        self.acl_content_dict = {
            'AppId': app_appid,  # 业务id
        }

    # 新增业务prototype命名如下，删除只需要将add改成del
    # HTTP: 网关【addhttp】隔离【addhttp_front、addhttp_front_post、addhttp_redirect_front】
    # FTP:  网关【addftp】 隔离【addftp_front】
    # MAIL: 网关【addsmtp】隔离【addsmtp_front】
    # TCP、UDP: 路由【addtcp/addudp】代理【addtcp_proxy/addudp_proxy】
    def setAccessconf(self, prototype=None, appId=None, proxy_ip=None, server_port=None, proxy_port=None,
                      L4protocol=None, Mode=None, sip=None, GapFromTo=None):
        # HTTP业务
        if 'http' in prototype:
            msg = self.http_agent(prototype=prototype, appId=appId, proxy_Ip=proxy_ip, proxy_port=proxy_port,
                                  server_port=server_port, GapFromTo=GapFromTo)
            return msg
        # FTP业务
        elif 'ftp' in prototype:
            msg = self.ftp_agent(prototype=prototype, appId=appId, dip=None, proxy_port=proxy_port)
            return msg
        # MAIL业务
        elif 'smtp' in prototype or 'pop3' in prototype:
            msg = self.mail_agent(prototype=prototype, appId=appId, proxy_port=proxy_port, Mode=Mode, sip=sip)
            return msg
        # TCP/UDP业务
        elif 'tcp' in prototype or 'udp' in prototype:
            msg = self.tcp_udp_interface(prototype=prototype, L4protocol=L4protocol, server_port=server_port,
                                         appId=appId,
                                         proxy_port=proxy_port, Mode=Mode, sip=sip)
            return msg

    # HTTP业务下发与移除
    def http_agent(self, prototype=None, appId=None, proxy_Ip=None, proxy_port=None, server_port=None, GapFromTo=None):

        # 代理接口的content
        if appId is not None:
            self.content_dict['AppId'] = appId
        else:
            if 'tcp' in prototype:
                self.content_dict['AppId'] = tcp_appid
            else:
                self.content_dict['AppId'] = http_appid
        if 'tcp' in prototype:
            self.content_dict['Module'] = ''
        else:
            self.content_dict['Module'] = http_module
        self.content_dict['Dip'] = http_server_ip
        self.content_dict['Sip'] = windows_sip
        if server_port is not None:
            self.content_dict['Dport'] = server_port
        else:
            self.content_dict['Dport'] = http_server_port
        if proxy_Ip is not None:
            self.content_dict['Lip'] = proxy_Ip
        else:
            self.content_dict['Lip'] = proxy_ip
        if proxy_port is not None:
            self.content_dict['Lport'] = proxy_port
        else:
            self.content_dict['Lport'] = http_proxy_port
        # 网关模块——新增http代理
        if 'addhttp' == prototype or 'add_tcp_http' == prototype:
            # 网关模块的content中，需要移除属性 GapFromTo
            self.content_dict.pop('GapFromTo')
            # 重新赋值到接口的content中
            all_interface.agent['agent']['Content'][0] = self.content_dict
            return all_interface.agent['agent']
        # 网关模块——删除http代理
        elif 'delhttp' == prototype or 'del_tcp_http' == prototype:
            # 该接口的appids属性，赋值该模块的appid
            if appId is not None:
                if isinstance(appId, list):
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = appId
                else:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [appId]
            else:
                if 'delhttp' == prototype:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [http_appid]
                else:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [tcp_appid]
            return all_interface.del_agent['agent']
        # 以下为隔离模块的代理接口逻辑处理
        if 'del' in prototype:
            if appId is not None:
                if isinstance(appId, list):
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = appId
                elif 'all' == appId:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = []
                else:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [appId]
            else:
                if 'del_tcp_http' in prototype:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [tcp_appid]
                else:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [http_appid]
            return all_interface.del_agent['agent']
        # 隔离模块的监听ip需要改为前置机的业务ip
        if proxy_Ip is None:
            self.content_dict.update(Lip=BG8010FrontOpeIp)
        if GapFromTo is not None:
            self.content_dict.update(GapFromTo=GapFromTo)

        log.warning(self.content_dict)
        # post方式和普通方式的，里层字典有三个参数不一样
        if 'post' in prototype:
            self.content_dict.update(Appid=http_post_appid, Dport=http_server_port_file,
                                     Lport=http_server_port_file)

            all_interface.agent['agent']['Content'][0] = self.content_dict
            return all_interface.agent['agent']
        # http服务器ip是统一的,redirect的端口不一样,10.10.100.201:8000重定向到10.10.101.22:8000，需要重新赋值
        elif 'redirect' in prototype:
            self.content_dict.update(Dport=http_redirect_port)
            all_interface.agent['agent']['Content'][0] = self.content_dict
            return all_interface.agent['agent']
        else:
            all_interface.agent['agent']['Content'][0] = self.content_dict
            return all_interface.agent['agent']

    # FTP业务下发与移除
    def ftp_agent(self, prototype=None, appId=None, dip=None, proxy_port=None):
        # 代理接口的content
        if appId is not None:
            self.content_dict['AppId'] = appId
        else:
            self.content_dict['AppId'] = ftp_appid
        self.content_dict['Module'] = ftp_module
        self.content_dict['Sip'] = windows_sip

        if dip is not None:
            self.content_dict['Dip'] = dip
        else:
            self.content_dict['Dip'] = ftp_ip
        self.content_dict['Dport'] = ftp_dport
        self.content_dict['Lip'] = proxy_ip
        if proxy_port is not None:
            self.content_dict['Lport'] = proxy_port
        else:
            self.content_dict['Lport'] = ftp_proxy_port

        if 'addftp' == prototype:
            # 网关模块的content中，需要移除属性 GapFromTo
            self.content_dict.pop('GapFromTo')
            all_interface.agent['agent']['MethodName'] = 'SetAccessConf'
            all_interface.agent['agent']['Content'][0] = self.content_dict
            return all_interface.agent['agent']
        elif 'delftp' == prototype:
            if appId is not None:
                all_interface.del_agent['agent']['Content'][0]['AppIds'] = [appId]
            else:
                # 该接口的appids属性，赋值该模块的appid
                all_interface.del_agent['agent']['Content'][0]['AppIds'] = [ftp_appid]
            return all_interface.del_agent['agent']

        # 以下为隔离模块的代理接口逻辑处理
        if 'del' in prototype:
            if appId is not None:
                if isinstance(appId, list):
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = appId
                elif 'all' == appId:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = []
                else:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [appId]
            else:
                all_interface.del_agent['agent']['Content'][0]['AppIds'] = [ftp_appid]
            return all_interface.del_agent['agent']
        # 隔离模块的监听ip需要改为前置机的业务ip
        self.content_dict.update(Lip=BG8010FrontOpeIp)
        all_interface.agent['agent']['Content'][0] = self.content_dict
        return all_interface.agent['agent']

    # MAIL邮件业务下发与移除
    def mail_agent(self, prototype=None, appId=None, proxy_port=None, Mode=None, sip=None):
        # 代理接口的content
        if 'smtp' in prototype:
            if appId is not None:
                self.content_dict['AppId'] = appId
            else:
                self.content_dict['AppId'] = smtp_appid
            self.content_dict['Module'] = smtp_module
            if sip is None:
                self.content_dict['Sip'] = windows_sip
            else:
                self.content_dict['Sip'] = sip
            self.content_dict['Dip'] = smtp_ip
            self.content_dict['Dport'] = smtp_server_port
            if Mode is not None and Mode == 0:
                self.content_dict['Mode'] = Mode
                self.content_dict['Lip'] = ""
                self.content_dict.pop('Lport')
            else:
                self.content_dict['Lip'] = proxy_ip
                if proxy_port is not None:
                    self.content_dict['Lport'] = proxy_port
                else:
                    self.content_dict['Lport'] = smtp_proxy_port
        elif 'pop3' in prototype:
            if appId is not None:
                self.content_dict['AppId'] = appId
            else:
                self.content_dict['AppId'] = pop3_appid
            self.content_dict['Module'] = pop3_module
            if sip is None:
                self.content_dict['Sip'] = windows_sip
            else:
                self.content_dict['Sip'] = sip
            self.content_dict['Dip'] = pop3_ip
            self.content_dict['Dport'] = pop3_server_port
            self.content_dict['Lip'] = proxy_ip
            if Mode is not None and Mode == 0:
                self.content_dict['Mode'] = Mode
                self.content_dict['Lip'] = ""
                self.content_dict.pop('Lport')
            else:
                if proxy_port is not None:
                    self.content_dict['Lport'] = proxy_port
                else:
                    self.content_dict['Lport'] = pop3_proxy_port
        if 'addsmtp' == prototype or 'addpop3' == prototype:
            # 网关模块的content中，需要移除属性 GapFromTo
            self.content_dict.pop('GapFromTo')
            all_interface.agent['agent']['MethodName'] = 'SetAccessConf'
            all_interface.agent['agent']['Content'][0] = self.content_dict
            return all_interface.agent['agent']
        elif 'delsmtp' == prototype:
            # 该接口的appids属性，赋值该模块的appid
            all_interface.del_agent['agent']['Content'][0]['AppIds'] = [smtp_appid]
            return all_interface.del_agent['agent']
        elif 'delpop3' == prototype:
            # 该接口的appids属性，赋值该模块的appid
            all_interface.del_agent['agent']['Content'][0]['AppIds'] = [pop3_appid]
            return all_interface.del_agent['agent']

        # 以下为隔离模块的代理接口逻辑处理
        if 'del' in prototype:
            if appId is not None:
                if isinstance(appId, list):
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = appId
                elif 'all' == appId:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = []
                else:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [appId]
            else:
                if 'smtp' in prototype:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [smtp_appid]
                else:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [pop3_appid]
            return all_interface.del_agent['agent']
        # 隔离模块的监听ip需要改为前置机的业务ip
        self.content_dict.update(Lip=BG8010FrontOpeIp)
        all_interface.agent['agent']['Content'][0] = self.content_dict
        return all_interface.agent['agent']

    # TCP和UDP业务下发与移除
    def tcp_udp_interface(self, prototype=None, L4protocol=None, server_port=None, appId=None, proxy_port=None,
                          Mode=None, sip=None, lip=None, dip=None, GapFromTo=None):
        ### TCP/UDP协议相关的增删改，包括网关路由模式，网关代理模式，隔离模式
        log.warning("要执行的操作是{}".format(prototype))

        # # 判断协议和操作是否一致，不一致给出提醒
        # if L4protocol is not None and L4protocol not in prototype and 'add' in prototype:
        #     log.warning("协议和操作名称不一致，请检查")
        #     sys.exit(0)

        # if appId is not None:
        #     self.content_dict['AppId'] = appId
        # else:
        #     self.content_dict['AppId'] = tcp_appid
        if appId is None:
            if 'tcp' in prototype:
                self.content_dict['AppId'] = tcp_appid
                appId = tcp_appid
            elif 'udp' in prototype:
                self.content_dict['AppId'] = udp_appid
                appId = udp_appid
        else:
            self.content_dict['AppId'] = appId

        if 'del' not in prototype and Mode != 0 and Mode != 1 and Mode != 2:
            log.warning("无效的代理模式，请确认后再执行")
            sys.exit(0)
        self.content_dict['Mode'] = Mode  # 配置路由、反向代理、透明代理模式

        # 代理（隔离）模式下存在代理IP和代理端口,反向代理的代理IP和代理端口是设备上的，透明代理是监听server，转发server
        if Mode == 2:
            # 针对循环下发代理业务的情况,通过代理端口的递增来实现
            if proxy_port is not None:
                self.content_dict['Lport'] = proxy_port
            else:
                self.content_dict['Lport'] = http_proxy_port
            log.warning('代理端口是{}'.format(self.content_dict['Lport']))
            # 代理IP
            self.content_dict['Lip'] = proxy_ip
            # 目标Ip
            self.content_dict['Dip'] = http_server_ip
        elif Mode == 1:
            # 针对循环下发代理业务的情况,通过代理端口的递增来实现
            if proxy_port is not None:
                self.content_dict['Lport'] = proxy_port
            else:
                self.content_dict['Lport'] = http_server_port
            log.warning('代理端口是{}'.format(self.content_dict['Lport']))
            # 代理IP
            self.content_dict['Lip'] = http_server_ip
            # 目标Ip
            self.content_dict['Dip'] = self.content_dict['Lip']

        if L4protocol is not None:
            self.content_dict['L4protocol'] = L4protocol

        self.content_dict['Module'] = ''  # 应用层协议
        if dip is not None:
            self.content_dict['Dip'] = dip
        if sip is not None:
            self.content_dict['Sip'] = sip
        else:
            self.content_dict['Sip'] = windows_sip

        # 针对循环添加业务的情况
        if server_port is not None:
            self.content_dict['Dport'] = server_port
        else:
            self.content_dict['Dport'] = http_server_port

        ## 添加TCP或者UDP业务
        if 'addtcp' == prototype or 'addudp' == prototype:  # 路由模式，只需要源IP，目的IP，目的端口，模式这几个参数
            if Mode != 0:  # 路由模式的判断
                log.warning('路由模式下mode需要为0，请检查输入参数')
                sys.exit(0)
            log.warning('网关路由下发参数组装')
            # 路由模式下代理IP为空
            self.content_dict['Lip'] = ''
            # 网关模块的content中，需要移除属性 GapFromTo（隔离模块）
            self.content_dict.pop('GapFromTo')
            # 网关路由模式下，也需要移除Lport
            self.content_dict.pop('Lport')
            # 重新赋值到接口的content中
            all_interface.agent['agent']['Content'][0] = self.content_dict
            return all_interface.agent['agent']

        # 删除TCP或者UDP业务
        elif 'deltcp' == prototype or 'deludp' == prototype:
            log.warning('删除业务')
            # 该接口的appids属性，赋值该模块的appid
            if appId is not None:
                if isinstance(appId, list):
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = appId
                else:
                    all_interface.del_agent['agent']['Content'][0]['AppIds'] = [appId]
            else:
                all_interface.del_agent['agent']['Content'][0]['AppIds'] = [app_appid]
            return all_interface.del_agent['agent']

        # 代理模式下添加TCP\UDP
        elif 'addtcp_proxy' == prototype or 'addudp_proxy' == prototype:
            if Mode == 0:
                log.warning('代理模式下mode需要为1或者2，请检查输入参数')
                sys.exit(0)
            log.warning('代理下发参数组装')
            # 代理模式，需要区分反向代理和透明代理。目前参数都一样，需要源IP，目的IP，目的端口，代理IP，代理端口，代理模式
            # 移除隔离参数
            self.content_dict.pop('GapFromTo')
            # udp需要将L4protocol属性改成udp
            if 'addudp_proxy' == prototype:
                self.content_dict.update(L4protocol='udp')
            # 重新赋值到接口的content中
            log.warning(self.content_dict)
            all_interface.agent['agent']['Content'][0] = self.content_dict
            return all_interface.agent['agent']

        # 隔离模式下添加TCP和UDP
        elif 'addtcp_iso' == prototype or 'addudp_iso' == prototype:
            if Mode != 2:
                log.warning('隔离模式暂时只支持反向代理，mode需要为2，请检查输入参数')
                sys.exit(0)
            # 隔离模式下，TCP和UDP业务包括源IP，目的IP，目的端口，代理IP，代理端口，代理模式，隔离通道参数
            # 隔离模块的监听ip需要改为前置机的业务ip
            if lip is not None:
                self.content_dict.update(Lip=lip)
            else:
                self.content_dict.update(Lip=BG8010FrontOpeIp)
            if GapFromTo is not None:
                self.content_dict.update(GapFromTo=GapFromTo)
            # 重新赋值到接口的content中
            log.warning(self.content_dict)
            all_interface.agent['agent']['Content'][0] = self.content_dict
            return all_interface.agent['agent']

        else:
            log.warning('未匹配上任何操作，请检查调用意图')
            sys.exit(0)

    # 应用安全策略
    def app_safe_policy(self, prototype=None, appId=None, ruleid=None, check_action='deny', content_dict=None,
                        uri_data=None, parameter=None, mime_data=None, method='GET',  # http
                        user_data=None, cmd_data=None, upload_data=None, download_data=None,  # ftp
                        mail_data=None, subject_data=None, attachmentExt_data=None):  # mail
        # HTTP模块
        if 'http' in prototype or 'tcp_http' in prototype:
            msg = self.http_check_data(prototype=prototype, check_action=check_action, appId=appId, uri_data=uri_data,
                                       ruleid=ruleid, mime_data=mime_data, parameter=parameter, method=method,
                                       content_dict=content_dict)
            return msg
        # FTP 模块
        elif 'ftp' in prototype:
            msg = self.ftp_check_data(prototype=prototype, ruleid=ruleid, check_action=check_action, appId=appId,
                                      user_data=user_data, cmd_data=cmd_data, upload_data=upload_data,
                                      download_data=download_data, content_dict=content_dict)
            return msg
        # mail 模块
        elif 'mail' in prototype or 'smtp' in prototype or 'pop3' in prototype:
            msg = self.mail_check_data(prototype=prototype, ruleid=ruleid, check_action=check_action, appId=appId,
                                       mail_data=mail_data, subject_data=subject_data,
                                       attachmentExt_data=attachmentExt_data, content_dict=content_dict)
            return msg
        else:
            log.warning('无匹配的接口名称，请确认后再执行')
            sys.exit(0)

    '''
    prototype必填，值为：httpcheck/delhttpcheck
    ruleid：如果为空，则默认http_ruleid，传参格式为：[数值]
    check_action：如果为空，则默认deny，传参格式为：'deny'/'allow'
    appId：如果为空，则默认http_appid，传参格式为：数值
    parameter|mime_data|uri_data，这几个参数，可以是字符串，表明是单个值，也可以是列表，表明是多个值
    content_dict：用于读表执行用例，传入字典格式的整个策略内容
    '''

    def http_check_data(self, prototype=None, check_action=None, method=None, parameter=None,
                        mime_data=None, ruleid=None, uri_data=None, appId=None, content_dict=None):
        # 判断策略内容是否完整完整传入，逻辑为读表数据
        if content_dict is not None:
            all_interface.SetDataCheck['SetDataCheck']['MethodName'] = "SetHttpCheck"
            if appId is not None:
                all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppId'] = appId
            else:
                all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppId'] = http_appid
            all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppRules'][0] = content_dict
            return all_interface.SetDataCheck['SetDataCheck']

        # 删除数据结构检查
        if 'delhttpcheck' == prototype:
            all_interface.DelCheck['DelCheck']['MethodName'] = "DelHttpCheck"
            if appId is not None:
                all_interface.DelCheck['DelCheck']['Content'][0].update(AppId=appId)
            else:
                all_interface.DelCheck['DelCheck']['Content'][0].update(AppId=http_appid)
            if ruleid is not None:
                all_interface.DelCheck['DelCheck']['Content'][0].update(RuleIds=ruleid)
            else:
                all_interface.DelCheck['DelCheck']['Content'][0].update(RuleIds=[http_ruleid])
            return all_interface.DelCheck['DelCheck']
        # 新增数据结构检查
        elif 'httpcheck' == prototype:
            data_check_dict = self.data_check_dict
            rules_dict = data_check_dict['AppRules'][0]
            if appId is not None:
                data_check_dict.update(AppId=appId)
            if check_action is not None:
                if 'deny' == check_action:
                    check_action = 'Deny'
                elif 'allow' == check_action:
                    check_action = 'Allow'
                rules_dict.update(Action=check_action)
            if ruleid is not None:
                rules_dict.update(RuleId=ruleid)
            if method is not None:
                method_list = []
                if isinstance(method, str):
                    method_list.append(method)
                else:
                    method_list = method
                rules_dict.update(Method=method_list)
            if parameter is not None:
                parameter_list = []
                if isinstance(parameter, str):
                    parameter_list.append(parameter)
                else:
                    parameter_list = parameter
                rules_dict.update(Parameter=parameter_list)
            if mime_data is not None:
                mime_list = []
                if isinstance(mime_data, str):
                    mime_list.append(mime_data)
                else:
                    mime_list = mime_data
                rules_dict.update(MIME=mime_list)
            if uri_data is not None:
                uri_list = []
                if isinstance(uri_data, str):
                    uri_list.append(uri_data)
                else:
                    uri_list = uri_data
                rules_dict.update(URI=uri_list)
            # log.warning('-----------{}'.format(all_interface.SetDataCheck['SetDataCheck']))
            all_interface.SetDataCheck['SetDataCheck']['MethodName'] = "SetHttpCheck"
            all_interface.SetDataCheck['SetDataCheck']['Content'][0] = data_check_dict
            return all_interface.SetDataCheck['SetDataCheck']

    '''
    prototype必填，值为：ftpcheck/delftpcheck
    ruleid：如果为空，则默认ftp_ruleid，传参格式为：[数值]
    check_action：如果为空，则默认deny，传参格式为：'deny'/'allow'
    appId：如果为空，则默认ftp_appid，传参格式为：数值
    user_data|cmd_data|upload_data|download_data，这几个参数，可以是字符串，表明是单个值，也可以是列表，表明是多个值
    content_dict：用于读表执行用例，传入字典格式的整个策略内容
    '''

    def ftp_check_data(self, prototype=None, appId=None, ruleid=None, check_action=None, user_data=None,
                       cmd_data=None, upload_data=None, download_data=None, content_dict=None):
        # 判断策略内容是否完整完整传入，逻辑为读表数据
        if content_dict is not None:
            all_interface.SetDataCheck['SetDataCheck']['MethodName'] = "SetFtpCheck"
            if appId is not None:
                all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppId'] = appId
            else:
                all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppId'] = ftp_appid
            all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppRules'][0] = content_dict
            return all_interface.SetDataCheck['SetDataCheck']

        rules_dict = {}
        # 删除数据结构检查
        if 'delftpcheck' == prototype:
            all_interface.DelCheck['DelCheck']['MethodName'] = "DelFtpCheck"
            if appId is not None:
                all_interface.DelCheck['DelCheck']['Content'][0].update(AppId=appId)
            else:
                all_interface.DelCheck['DelCheck']['Content'][0].update(AppId=ftp_appid)
            if ruleid is not None:
                all_interface.DelCheck['DelCheck']['Content'][0].update(RuleIds=ruleid)
            else:
                all_interface.DelCheck['DelCheck']['Content'][0].update(RuleIds=[ftp_ruleid])
            return all_interface.DelCheck['DelCheck']
        # 新增数据结构检查
        elif 'ftpcheck' == prototype:
            rules_dict = self.data_check_dict['AppRules'][0]
        if check_action is not None:
            if 'deny' == check_action:
                check_action = 'Deny'
            elif 'allow' == check_action:
                check_action = 'Allow'
            rules_dict.update(Action=check_action)
        if ruleid is not None:
            rules_dict.update(RuleId=ruleid)
        else:
            rules_dict.update(RuleId=ftp_ruleid)
        if user_data is not None:
            user_list = []
            if isinstance(user_data, str):
                user_list.append(user_data)
            else:
                user_list = user_data
            rules_dict.update(User=user_list)
        if cmd_data is not None:
            cmd_list = []
            if isinstance(cmd_data, str):
                ls = cmd_data.split(';')
                if len(ls) == 1:
                    cmd_list.append(cmd_data)
                else:
                    cmd_list = ls
            else:
                cmd_list = cmd_data
            rules_dict.update(Cmd=cmd_list)
        if upload_data is not None:
            upload_list = []
            if isinstance(upload_data, str):
                upload_list.append(upload_data)
            else:
                upload_list = upload_data
            rules_dict.update(UploadExt=upload_list)
        if download_data is not None:
            download_list = []
            if isinstance(download_data, str):
                download_list.append(download_data)
            else:
                download_list = download_data
            rules_dict.update(DownloadExt=download_list)
        all_interface.SetDataCheck['SetDataCheck']['MethodName'] = "SetFtpCheck"
        all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppId'] = ftp_appid
        all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppRules'][0] = rules_dict
        return all_interface.SetDataCheck['SetDataCheck']

    '''
    prototype必填，值为：mailcheck/delmailcheck
    ruleid：如果为空，则默认smtp_ruleid，传参格式为：[数值]
    check_action：如果为空，则默认deny，传参格式为：'deny'/'allow'
    appId：如果为空，则默认smtp_appid，传参格式为：数值
    mail_data|subject_data|attachmentExt_data，这几个参数，可以是字符串，表明是单个值，也可以是列表，表明是多个值
    content_dict：用于读表执行用例，传入字典格式的整个策略内容
    '''

    def mail_check_data(self, prototype=None, ruleid=None, check_action=None, appId=None, mail_data=None,
                        subject_data=None, attachmentExt_data=None, content_dict=None):
        # 判断策略内容是否完整完整传入，逻辑为读表数据
        if content_dict is not None:
            all_interface.SetDataCheck['SetDataCheck']['MethodName'] = "SetMailCheck"
            if appId is not None:
                all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppId'] = appId
            else:
                all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppId'] = smtp_appid
            all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppRules'][0] = content_dict
            return all_interface.SetDataCheck['SetDataCheck']

        # 删除数据结构检查
        if 'delmailcheck' == prototype:
            all_interface.DelCheck['DelCheck']['MethodName'] = "DelMailCheck"
            if appId is not None:
                all_interface.DelCheck['DelCheck']['Content'][0].update(AppId=appId)
            else:
                all_interface.DelCheck['DelCheck']['Content'][0].update(AppId=smtp_appid)
            if ruleid is not None:
                all_interface.DelCheck['DelCheck']['Content'][0].update(RuleIds=ruleid)
            else:
                all_interface.DelCheck['DelCheck']['Content'][0].update(RuleIds=[smtp_ruleid])
            return all_interface.DelCheck['DelCheck']
        # 新增数据结构检查
        elif 'mailcheck' == prototype:
            rules_dict = self.data_check_dict['AppRules'][0]
            if check_action is not None:
                if 'deny' == check_action:
                    check_action = 'Deny'
                elif 'allow' == check_action:
                    check_action = 'Allow'
                rules_dict.update(Action=check_action)
            if ruleid is not None:
                rules_dict.update(RuleId=ruleid)
            else:
                rules_dict.update(RuleId=smtp_ruleid)
            if mail_data is not None:
                mail_list = []
                if isinstance(mail_data, str):
                    ls = mail_data.split(';')
                    if len(ls) == 1:
                        mail_list.append(mail_data)
                    else:
                        mail_list = ls
                else:
                    mail_list = mail_data
                rules_dict.update(FromTo=mail_list)
            if subject_data is not None:
                subject_list = []
                if isinstance(subject_data, str):
                    ls = subject_data.split(';')
                    if len(ls) == 1:
                        subject_list.append(subject_data)
                    else:
                        subject_list = ls
                else:
                    subject_list = subject_data
                rules_dict.update(Subject=subject_list)
            if attachmentExt_data is not None:
                attachmentExt_list = []
                if isinstance(attachmentExt_data, str):
                    ls = attachmentExt_data.split(';')
                    if len(ls) == 1:
                        attachmentExt_list.append(attachmentExt_data)
                    else:
                        attachmentExt_list = ls
                else:
                    attachmentExt_list = attachmentExt_data
                rules_dict.update(AttachmentExt=attachmentExt_list)
            all_interface.SetDataCheck['SetDataCheck']['MethodName'] = "SetMailCheck"
            all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppId'] = smtp_appid
            all_interface.SetDataCheck['SetDataCheck']['Content'][0]['AppRules'][0] = rules_dict
            return all_interface.SetDataCheck['SetDataCheck']

    # 关键字过滤策略接口
    # appid为应用策略id
    # ruleid为策略id,管控从1开始累加，可以传参，否则默认处理成100开始累加
    # spattern：转码前内容，比如为：卓讯
    # pattern：base64转码后内容,比如为 5Y2T6K6v，如果不转码，则就为原数据
    # 格式如下：keyword_interface(appid=1, pattern='test1;test2;test3', spattern='1;2;3')
    def keyword_interface(self, appid=1, ruleid=None, spattern=None, pattern=None, flags_num=1, content_dict=None):
        # 判断策略内容是否完整完整传入，逻辑为读表数据
        if content_dict is not None:
            if appid is not None:
                all_interface.SetKeywordScan['SetKeywordScan']['Content'][0]['AppId'] = appid
            else:
                all_interface.SetKeywordScan['SetKeywordScan']['Content'][0]['AppId'] = tcp_appid
            all_interface.SetKeywordScan['SetKeywordScan']['Content'][0]['AppRules'].append(content_dict)
            return all_interface.SetKeywordScan['SetKeywordScan']

        # 如果ruleid不为空，则将内容以;拆分为list
        # 如果是'2'，则说明是2个ruleid，并且从101累加
        # 如果是2，则ruleid 为[2]
        # 如果是[1,2]，则直接传入列表，多个也可以用字符串形式的传法，例如:'1;2;3;4'
        if ruleid is not None:
            ruleids = []
            if isinstance(ruleid, str):
                for i in range(int(ruleid)):
                    ruleids.append(i + 101)
            elif isinstance(ruleid, list):
                ruleids = ruleid
            elif isinstance(ruleid, int):
                ruleids = [ruleid]
            else:
                ruleids = ruleid.split(';')
        else:
            # 如果为空，则以pattern的长度来累加，内容为[101,102,103,……]
            if pattern is not None:
                ruleids = []
                l = pattern.split(';')
                for i in range(len(l)):
                    ruleids.append(i + 101)
            # 如果pattern也为空，则默认固定数据
            else:
                ruleids = [1, 2, 3, 4, 5, 6]
        # 如果spattern不为空，则表示是base64转码的，pattern为转码后的内容，所以两个入参的长度得对应上
        if spattern is not None:
            spatterns = spattern.split(';')
            patterns = pattern.split(';')
            if len(spatterns) != len(patterns):
                log.warning('转码前后数据量不一致，pattern和spattern的入参长度应保持一致')
                sys.exit(0)
        if pattern is not None:
            # 添加关键字过滤【内容审查】策略content
            rules = []
            keyword_rule_dict = {}
            self.keyword_content_dict['AppId'] = appid
            if isinstance(pattern, str):
                ls = pattern.split(';')
                if len(ls) == 1:
                    keyword_rule_dict.update(Pattern=pattern)
                    if ruleid is not None:
                        keyword_rule_dict.update(RuleId=ruleid)
                    else:
                        keyword_rule_dict.update(RuleId=101)
                    if spattern is not None:
                        keyword_rule_dict.update(SPattern=spatterns[0])
                    if flags_num == 1:
                        keyword_rule_dict.update(Flags="FLAG_CASELESS")
                    rules.append(keyword_rule_dict)
                else:
                    for i in range(len(ls)):
                        keyword_rule_dict = {}
                        keyword_rule_dict.update(Pattern=ls[i], RuleId=int(ruleids[i]))
                        if spattern is not None:
                            keyword_rule_dict.update(SPattern=spatterns[i])
                        if flags_num == 1:
                            keyword_rule_dict.update(Flags="FLAG_CASELESS")
                        rules.append(keyword_rule_dict)
                        # log.warning('keyword_rule_dict:{}'.format(keyword_rule_dict))
                # log.warning('rules:{}'.format(rules))
                self.keyword_content_dict['AppRules'] = rules
                # log.warning('self.keyword_content_dict:{}'.format(self.keyword_content_dict))
            else:
                log.warning('pattern类型必须为字符串，类型错误，请检查后再运行')
                sys.exit(0)
            all_interface.SetKeywordScan['SetKeywordScan']['Content'][0] = self.keyword_content_dict
            return all_interface.SetKeywordScan['SetKeywordScan']
        elif pattern is None:
            # pattern为None，则表示这是移除关键字过滤策略
            all_interface.DelCheck['DelCheck']['MethodName'] = 'DelKeywordScan'
            if appid is not None:
                all_interface.DelCheck['DelCheck']['Content'][0]['AppId'] = appid
            else:
                all_interface.DelCheck['DelCheck']['Content'][0]['AppId'] = 1
            all_interface.DelCheck['DelCheck']['Content'][0]['RuleIds'] = ruleids
            return all_interface.DelCheck['DelCheck']

    # 定制应用
    def UDA_app_interface(self, appid=None, content_dict=None, ruleid=None):
        # 判断策略内容是否完整完整传入，逻辑为读表数据
        if content_dict is not None:
            if appid is not None:
                all_interface.SetUDACheck['SetUDACheck']['Content'][0]['AppId'] = appid
            else:
                all_interface.SetUDACheck['SetUDACheck']['Content'][0]['AppId'] = tcp_appid
            all_interface.SetUDACheck['SetUDACheck']['Content'][0]['AppRules'][0] = content_dict
            return all_interface.SetUDACheck['SetUDACheck']
        elif ruleid is not None:
            # 如果ruleId不为空，则表明这是移除定制应用策略
            all_interface.DelCheck['DelCheck']['MethodName'] = 'DelUDACheck'
            if appid is not None:
                all_interface.DelCheck['DelCheck']['Content'][0]['AppId'] = appid
            else:
                all_interface.DelCheck['DelCheck']['Content'][0]['AppId'] = tcp_appid
            if isinstance(ruleid, int):
                all_interface.DelCheck['DelCheck']['Content'][0]['RuleIds'] = [ruleid]
            elif isinstance(ruleid, str):
                all_interface.DelCheck['DelCheck']['Content'][0]['RuleIds'] = [int(ruleid)]
            elif isinstance(ruleid, list):
                all_interface.DelCheck['DelCheck']['Content'][0]['RuleIds'] = ruleid
            return all_interface.DelCheck['DelCheck']

    def cipso_agent_interface(self, appId=None, prototype=None, L4protocol='tcp'):
        """
        下发标记的业务访问配置接口
        :param prototype:
        :return:
        """
        # 业务模式为 路由模式
        self.content_dict['Mode'] = 0
        if appId is not None:
            self.content_dict['AppId'] = appId
        else:
            self.content_dict['AppId'] = cipso_appid
        # 源IP
        self.content_dict['Sip'] = clientOpeIp
        # 目的IP
        self.content_dict['Dip'] = serverOpeIp
        # 目的端口
        self.content_dict['Dport'] = http_server_port
        # 传输层协议
        self.content_dict['L4protocol'] = L4protocol
        # 应用层协议
        self.content_dict['Module'] = http_module
        self.content_dict.pop('GapFromTo')
        # 移除反向代理IP
        self.content_dict['Lip'] = ""
        # self.content_dict.pop('Lip')
        # 移除反向代理端口
        self.content_dict.pop('Lport')
        all_interface.agent['agent']['MethodName'] = 'SetAccessConf'
        log.warning(self.content_dict)
        if 'addAgent' == prototype:
            all_interface.agent['agent']['Content'][0] = self.content_dict
            return all_interface.agent['agent']
        elif 'delAgent' == prototype:
            all_interface.del_agent['agent']['Content'][0]['AppIds'] = [cipso_appid]
            return all_interface.del_agent['agent']
        else:
            log.warning('无匹配类型，请检查后再运行')
            sys.exit(0)

    def cipso_selabel_interface(self, appId=None, prototype=None, mtLabel=None, tgLabel=None, rvMtLabel=None,
                                rvTgLabel=None):
        """
        下发标记策略的配置接口
        :param prototype:
        :return:
        """
        if mtLabel is not None:
            self.cipso_content_dict.update(mtLabel)
        if tgLabel is not None:
            self.cipso_content_dict.update(tgLabel)
        if rvMtLabel is not None:
            self.cipso_content_dict.update(rvMtLabel)
        if rvTgLabel is not None:
            self.cipso_content_dict.update(rvTgLabel)
        log.warning(self.cipso_content_dict)
        if 'addSelabel' == prototype:
            all_interface.SetSelabel['SetSelabel']['Content'][0] = self.cipso_content_dict
            if appId is not None:
                all_interface.SetSelabel['SetSelabel']['Content'][0]['AppId'] = appId
            return all_interface.SetSelabel['SetSelabel']
        elif 'delSelabel' == prototype:
            if appId is not None:
                all_interface.DelSelabel['DelSelabel']['Content'][0]['AppId'] = appId
            return all_interface.DelSelabel['DelSelabel']
        else:
            log.warning('无匹配类型，请检查后再运行')
            sys.exit(0)

    def acl_interface(self, appId=None, prototype=None, content=None):
        """
        下发ACL策略的配置接口
        :param prototype:
        :return:
        """
        if content is not None:
            self.acl_content_dict.update(content)
        if appId is not None:
            self.acl_content_dict['AppId'] = appId
        log.warning(self.acl_content_dict)
        if 'addAcl' == prototype:
            all_interface.SetAcl['SetAcl']['Content'][0] = self.acl_content_dict
            return all_interface.SetAcl['SetAcl']
        elif 'delAcl' == prototype:
            if appId is not None:
                all_interface.DelAcl['DelAcl']['Content'][0] = self.acl_content_dict
            return all_interface.DelAcl['DelAcl']
        else:
            log.warning('无匹配类型，请检查后再运行')
            sys.exit(0)


if __name__ == '__main__':
    # msg1 = interface().keyword_interface(appid=1, pattern='test1;test2;test3', spattern='1;2;3')
    # msg = interface().setAccessconf(appId=0, prototype='addtcp_proxy', Mode=2, server_port=2288, proxy_port=2288)
    # log.warning(msg)
    # log.warning('=========================================================================\n')
    # msg1 = interface().setAccessconf(appId=0, prototype='addudp_proxy', Mode=2, server_port=2289, proxy_port=2289)
    # log.warning(msg1)
    # log.warning('=========================================================================\n')

    # msg2 = interface().setAccessconf(prototype='deltcp', Mode=2)
    # msg2 = interface().app_safe_policy(prototype='delmailcheck', appId=1, ruleid=[111])
    # msg2 = interface().UDA_app_interface(ruleid=107)

    # c = {'Pattern': '.aa', 'Flags': 'FLAG_DOTALL', 'RuleId': 102}
    # msg2 = interface().keyword_interface(content_dict=c)
    # msg2 = interface().mail_check_data(content_dict=c)
    msg2 = interface().setAccessconf(appId=0, prototype='deltcp')

    log.warning(msg2)
    # log.warning('=========================================================================\n')
