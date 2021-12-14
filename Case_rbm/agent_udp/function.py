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
    from Case_rbm.agent_udp import index
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
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
url = baseinfo.http_proxy_url
http_content = baseinfo.http_content

proxy_ip = baseinfo.gwClientIp


class Test_agent_udp():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        #fun.ssh_httpServer.connect()
        self.clr_env = clr_env
        self.curl1 = index.curl1
        self.curl2 = index.curl2

        clr_env.clear_env()


    @allure.feature('用例一：验证网关设备下udp协议的反向代理策略')
    def test_agent_udp_re(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(prototype='addudp_proxy', L4protocol='udp', Mode=2), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='gw', type='udp')

        fun.cmd(f'rm -rf /opt/pkt/{self.curl1["curl"][2]}', 'c')
        # 客户端发送udp请求
        log.warning('在客户端使用命令发送udp请求验证联通性')
        log.warning(self.curl1["curl"][0])
        fun.cmd(self.curl1["curl"][0], 'c')
        re = fun.wait_data(self.curl1["curl"][1], 'c', self.curl1["curl"][2], '检查udp请求', 100)
        assert self.curl1["curl"][2] in re
        log.warning('正常udp请求发送成功')

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().tcp_udp_interface(prototype='deludp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='gw', type='udp', flag=False)

    @allure.feature('用例二：验证网关设备下udp协议的透明代理策略')
    def test_agent_udp_tr(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(prototype='addudp_proxy', L4protocol='udp', Mode=1), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='gw', type='udp', mode=1)

        # 客户端发送http请求
        log.warning('在客户端使用命令发送udp请求验证联通性')
        log.warning(self.curl2["curl"][0])
        fun.cmd(self.curl2["curl"][0], 'c')
        re = fun.wait_data(self.curl2["curl"][1], 'c', self.curl2["curl"][2], '检查udp请求', 100)
        assert self.curl2["curl"][2] in re
        log.warning('正常udp请求发送成功')

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().tcp_udp_interface(prototype='deludp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='gw', type='tcp', mode=1, flag=False)




    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
