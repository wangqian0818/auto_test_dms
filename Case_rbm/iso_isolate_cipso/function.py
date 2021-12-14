# encoding='utf-8'
try:
    import os, sys, pytest, allure, time, re, time, logging
    log = logging.getLogger(__name__)
except Exception as err:
    print('导入CPython内置函数库失败!错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

base_path = os.path.dirname(os.path.abspath(__file__))  # 获取当前项目文件夹
base_path = base_path.replace('\\', '/')
sys.path.insert(0, base_path)  # 将当前目录添加到系统环境变量,方便下面导入版本配置等文件
log.warning(base_path)
try:
    from Case_rbm.iso_isolate_cipso import index
    from common import fun, tool, clr_env
    import common.ssh as c_ssh
except Exception as err:
    log.warning(
        '导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误

from common import baseinfo
from common.rabbitmq import *
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain

proxy_ip = baseinfo.BG8010FrontOpeIp

BG8010ClientOpeIp = baseinfo.BG8010ClientOpeIp
BG8010ServerOpeIp = baseinfo.BG8010ServerOpeIp
BG8010BackOpeIpInside = baseinfo.BG8010BackOpeIpInside
rbmExc = baseinfo.rbmExc
http_content = baseinfo.http_content
tcp_appid = baseinfo.tcp_appid
http_proxy_port = baseinfo.http_proxy_port
http_server_port = baseinfo.http_server_port

class Test_iso_isolate_cipso():

    def setup_class(self):
        # 获取参数
        fun.ssh_c.connect()
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        fun.ssh_BG8010Client.connect()
        fun.ssh_BG8010Server.connect()

        self.case1_mtLabel = index.case1_mtLabel
        self.case_curl = index.case_curl
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case2_gapFromTo = index.case2_gapFromTo
        self.case2_curl = index.case2_curl
        self.case2_step1 = index.case2_step1
        self.case2_step2 = index.case2_step2
        clr_env.iso_setup_class(dut='FrontDut')


    @allure.feature('用例一：验证隔离设备的带标记通信情况(A-B)')
    def test_iso_isolate_cipso_AB(self):
        # 下发配置
        log.warning('用例一：验证隔离设备的带标记通信情况(A-B)')
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addtcp_iso', Mode=2, sip=BG8010ClientOpeIp), FrontDomain, base_path)
        time.sleep(1)
        fun.send(rbmExc, tool.interface().cipso_selabel_interface(appId=tcp_appid, prototype='addSelabel',
                                                                  mtLabel=self.case1_mtLabel), FrontDomain, base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='tcp')
        # 检查安全标记策略是否下发成功
        log.warning('检查设备安全标记策略是否下发成功：')
        mtLabelStr = fun.change_check_labelStr(self.case1_mtLabel)
        re = fun.wait_data(type=6, dut='FrontDut', context=mtLabelStr, number=100)
        log.warning('预期包含内容：{}'.format(mtLabelStr))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert mtLabelStr in re

        # 客户端和服务端iptables初始化
        log.warning('客户端和服务端iptables初始化')
        while True:
            re = fun.wait_data(type=7, dut='BG8010Client')
            log.warning(re)
            if self.case1_step2["step1"][1] not in re:
                break
            fun.cmd(self.case1_step2["step1"][0], 'BG8010Client')
        while True:
            re = fun.wait_data(type=7, dut='BG8010Server')
            log.warning(re)
            if self.case1_step2["step2"][1] not in re:
                break
            fun.cmd(self.case1_step2["step2"][0], 'BG8010Server')
        # 客户端通过ssh下发配置并检查结果
        log.warning('客户端下发管理口标记策略')
        fun.cmd(self.case1_step1["step1"][0], 'BG8010Client')
        re = fun.wait_data(type=7, dut='BG8010Client', context=self.case1_step1["step1"][1], number=10)
        log.warning('预期包含内容：{}'.format(self.case1_step1["step1"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case1_step1["step2"][1] in re
        # 服务端通过ssh下发配置并检查结果
        log.warning('服务端通过ssh下发配置并检查结果')
        fun.cmd(self.case1_step1["step2"][0], 'BG8010Server')
        re = fun.wait_data(type=7, dut='BG8010Server', context=self.case1_step1["step2"][1], number=100)
        log.warning('预期包含内容：{}'.format(self.case1_step1["step2"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case1_step1["step2"][1] in re

        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case_curl["curl"][2]}', 'BG8010Client')
        log.warning('在客户端使用curl命令发送http请求验证联通性')
        log.warning(self.case_curl["curl"][0])
        fun.cmd(self.case_curl["curl"][0], 'BG8010Client')
        re = fun.wait_data(self.case_curl["curl"][1], 'BG8010Client', self.case_curl["curl"][2], '检查http请求', 100)
        assert self.case_curl["curl"][2] in re
        log.warning('正常http请求发送成功')


        # 客户端移除管理口标记策略
        log.warning('客户端移除管理口标记策略')
        fun.cmd(self.case1_step2["step1"][0], 'BG8010Client')
        re = fun.wait_data(type=7, dut='BG8010Client', context=self.case1_step2["step1"][1], number=1, flag=False)
        log.warning('预期包含内容：{}'.format(self.case1_step2["step1"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case1_step2["step1"][1] not in re

        # 服务端移除管理口标记策略
        log.warning('服务端移除管理口标记策略')
        log.warning(self.case1_step2["step2"][0])
        fun.cmd(self.case1_step2["step2"][0], 'BG8010Server')
        re = fun.wait_data(type=7, dut='BG8010Server', context=self.case1_step2["step2"][1], number=1, flag=False)
        log.warning('预期包含内容：{}'.format(self.case1_step2["step2"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case1_step2["step2"][1] not in re

        # 移除ACL策略
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='delAcl'), FrontDomain, base_path)
        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deltcp'), FrontDomain, base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='tcp', flag=False)

    @allure.feature('用例二：验证隔离设备的带标记通信情况(B-A)')
    def test_iso_isolate_cipso_BA(self):
        # 下发配置
        log.warning('用例二：验证隔离设备的带标记通信情况(B-A)')
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addtcp_iso', Mode=2,
                                            sip=BG8010ServerOpeIp, dip=BG8010ClientOpeIp, lip=BG8010BackOpeIpInside,
                                                            GapFromTo=self.case2_gapFromTo), FrontDomain, base_path)
        time.sleep(1)
        fun.send(rbmExc, tool.interface().cipso_selabel_interface(appId=tcp_appid, prototype='addSelabel',
                                                                  mtLabel=self.case1_mtLabel), FrontDomain, base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='BackDut', p_ip=BG8010BackOpeIpInside, type='tcp')
        # 检查安全标记策略是否下发成功
        log.warning('检查设备安全标记策略是否下发成功：')
        mtLabelStr = fun.change_check_labelStr(self.case1_mtLabel)
        re = fun.wait_data(type=6, dut='BackDut', context=mtLabelStr, number=100)
        log.warning('预期包含内容：{}'.format(mtLabelStr))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert mtLabelStr in re

        # 客户端和服务端iptables初始化
        log.warning('客户端和服务端iptables初始化')
        while True:
            re = fun.wait_data(type=7, dut='BG8010Server')
            log.warning(re)
            if self.case2_step2["step1"][1] not in re:
                break
            fun.cmd(self.case2_step2["step1"][0], 'BG8010Server')
        while True:
            re = fun.wait_data(type=7, dut='BG8010Client')
            log.warning(re)
            if self.case2_step2["step2"][1] not in re:
                break
            fun.cmd(self.case2_step2["step2"][0], 'BG8010Client')
        # 客户端通过ssh下发配置并检查结果
        log.warning('端下发管理口标记策略')
        fun.cmd(self.case2_step1["step1"][0], 'BG8010Server')
        re = fun.wait_data(type=7, dut='BG8010Server', context=self.case2_step1["step1"][1], number=10)
        log.warning('预期包含内容：{}'.format(self.case2_step1["step1"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case2_step1["step2"][1] in re
        # 服务端通过ssh下发配置并检查结果
        log.warning('服务端通过ssh下发配置并检查结果')
        fun.cmd(self.case2_step1["step2"][0], 'BG8010Client')
        re = fun.wait_data(type=7, dut='BG8010Client', context=self.case2_step1["step2"][1], number=100)
        log.warning('预期包含内容：{}'.format(self.case2_step1["step2"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case2_step1["step2"][1] in re

        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case2_curl["curl"][2]}', 'BG8010Server')
        log.warning('在客户端使用curl命令发送http请求验证联通性')
        log.warning(self.case2_curl["curl"][0])
        fun.cmd(self.case2_curl["curl"][0], 'BG8010Server')
        re = fun.wait_data(self.case2_curl["curl"][1], 'BG8010Server', self.case2_curl["curl"][2], '检查http请求', 100)
        assert self.case2_curl["curl"][2] in re
        log.warning('正常http请求发送成功')

        # 客户端移除管理口标记策略
        log.warning('客户端移除管理口标记策略')
        fun.cmd(self.case2_step2["step1"][0], 'BG8010Server')
        re = fun.wait_data(type=7, dut='BG8010Server', context=self.case2_step2["step1"][1], number=1, flag=False)
        log.warning('预期包含内容：{}'.format(self.case2_step2["step1"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case2_step2["step1"][1] not in re

        # 服务端移除管理口标记策略
        log.warning('服务端移除管理口标记策略')
        log.warning(self.case2_step2["step2"][0])
        fun.cmd(self.case2_step2["step2"][0], 'BG8010Client')
        re = fun.wait_data(type=7, dut='BG8010Client', context=self.case2_step2["step2"][1], number=1, flag=False)
        log.warning('预期包含内容：{}'.format(self.case2_step2["step2"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case2_step2["step2"][1] not in re

        # 移除ACL策略
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='delAcl'), FrontDomain, base_path)
        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deltcp'), FrontDomain,
                 base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='BackDut', p_ip=BG8010BackOpeIpInside, type='tcp', flag=False)


    def teardown_class(self):
        # 回收环境
        clr_env.iso_teardown_met('http', base_path)
        clr_env.iso_teardown_met('http_post', base_path)
        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')
        fun.rbm_close()
        fun.ssh_close('FrontDut')

