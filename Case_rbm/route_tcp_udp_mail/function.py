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
    from Case_rbm.route_tcp_udp_mail import index
    from common import fun, tool
    import common.ssh as c_ssh
except Exception as err:
    log.warning(
        '导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误

from common import baseinfo
from common import clr_env
from common.rabbitmq import *

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
rbmDomain = baseinfo.rbmDomain
clientOpeIp = baseinfo.clientOpeIp
rbmExc = baseinfo.rbmExc
tcp_appid = baseinfo.tcp_appid
smtp_appid = baseinfo.smtp_appid
pop3_appid = baseinfo.pop3_appid
smtp_ip = baseinfo.smtp_ip
pop3_ip = baseinfo.pop3_ip
smtp_server_port = baseinfo.smtp_server_port
pop3_server_port = baseinfo.pop3_server_port


class Test_route_tcp_udp_mail():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env
        self.case1_curl = index.case1_curl
        self.case2_curl = index.case2_curl
        self.case3_smtp = index.case3_smtp
        self.case3_pop3 = index.case3_pop3

        clr_env.clear_env()


    @allure.feature('用例一：验证路由模式下协议为tcp情况')
    def test_route_tcp(self):
        log.warning('用例一：验证路由模式下协议为tcp情况')
        # 下发业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addtcp', Mode=0), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert clientOpeIp in re
        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case1_curl["curl"][2]}', 'c')
        log.warning('在客户端发送tcp请求验证联通性')
        log.warning(self.case1_curl["curl"][0])
        fun.cmd(self.case1_curl["curl"][0], 'c')
        re = fun.wait_data(self.case1_curl["curl"][1], 'c', self.case1_curl["curl"][2], '检查tcp请求', 100)
        assert self.case1_curl["curl"][2] in re
        log.warning('正常tcp请求发送成功')

        # 移除业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deltcp', Mode=0), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert clientOpeIp not in re

    @allure.feature('用例一：验证路由模式下协议为udp情况')
    def test_route_udp(self):
        log.warning('用例一：验证路由模式下协议为udp情况')
        # 下发业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addudp', L4protocol='udp', Mode=0), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert clientOpeIp in re

        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case2_curl["curl"][2]}', 'c')
        log.warning('在客户端发送udp请求验证联通性')
        log.warning(self.case2_curl["curl"][0])
        fun.cmd(self.case2_curl["curl"][0], 'c')
        re = fun.wait_data(self.case2_curl["curl"][1], 'c', self.case2_curl["curl"][2], '检查udp请求', 100)
        assert self.case2_curl["curl"][2] in re
        log.warning('正常udp请求发送成功')

        # 移除业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deludp', Mode=0), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert clientOpeIp not in re


    @allure.feature('用例三：验证路由模式下协议为smtp和pop3的情况')
    def test_route_smtp_pop3(self):
        log.warning('用例三：验证路由模式下协议为smtp和pop3的情况')
        # [Sip,sp,dip,dp,l4p]
        smtp_check = [clientOpeIp, '0', smtp_ip, str(smtp_server_port)]
        pop3_check = [clientOpeIp, '0', pop3_ip, str(pop3_server_port)]

        # 下发业务配置smtp
        fun.send(rbmExc, tool.interface().setAccessconf(appId=smtp_appid, prototype='addsmtp', Mode=0, sip=clientOpeIp), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(smtp_check)[1:-1] in str(re.split())[1:-1]
        # 下发业务配置pop3
        fun.send(rbmExc, tool.interface().setAccessconf(appId=pop3_appid, prototype='addpop3', Mode=0, sip=clientOpeIp), rbmDomain, base_path)

        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(pop3_check)[1:-1] in str(re.split())[1:-1]
        # 发送smtp
        fun.cmd(f'rm -rf /opt/pkt/{self.case3_smtp["curl"][2]}', 'c')
        log.warning('发送smtp')
        log.warning(self.case3_smtp["curl"][0])
        fun.cmd(self.case3_smtp["curl"][0], 'c', timeout=20)
        time.sleep(5)
        re = fun.wait_data(self.case3_smtp["curl"][1], 'c', self.case3_smtp["curl"][2], '检查smtp', 10)
        assert self.case3_smtp["curl"][2] in re
        log.warning('smtp发送成功')
        time.sleep(10)
        # 接收pop3
        fun.cmd(f'rm -rf /opt/pkt/{self.case3_pop3["curl"][2]}', 'c')
        log.warning('接收pop3')
        log.warning(self.case3_pop3["curl"][0])
        fun.cmd(self.case3_pop3["curl"][0], 'c', timeout=20)
        time.sleep(5)
        re = fun.wait_data(self.case3_pop3["curl"][1], 'c', self.case3_pop3["curl"][2], '检查pop3', 10)
        assert self.case3_pop3["curl"][2] in re
        log.warning('pop3接收成功')
        # 移除业务配置
        fun.send(rbmExc, tool.interface().setAccessconf(appId=smtp_appid, prototype='delsmtp', Mode=0), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(smtp_check)[1:-1] not in str(re.split())[1:-1]
        fun.send(rbmExc, tool.interface().setAccessconf(appId=pop3_appid, prototype='delpop3', Mode=0), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(pop3_check)[1:-1] not in str(re.split())[1:-1]

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
