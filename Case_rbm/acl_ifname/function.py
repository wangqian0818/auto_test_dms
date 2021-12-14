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
    from Case_rbm.acl_ifname import index
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
rbmExc = baseinfo.rbmExc
tcp_appid = baseinfo.tcp_appid

class Test_acl_ifname():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env
        self.case1_content = index.case1_content
        self.case1_curl = index.case1_curl
        clr_env.clear_env()


    @allure.feature('用例一：验证网络安全策略下发Bond接口动作执行为允许的情况')
    def test_acl_ifname_bond_allow(self):
        log.warning('用例一：验证网络安全策略下发Bond接口动作执行为允许的情况')
        # 下发业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addtcp', Mode=0), rbmDomain, base_path)
        # 下发ACL策略
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case1_content), rbmDomain, base_path)
        log.warning('检查策略是否下发成功：')
        re = fun.wait_data(type=6, dut='gw',context=str(self.case1_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) in re

        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case1_curl["curl"][2]}', 'c')
        log.warning('在客户端使用curl命令发送http请求验证联通性')
        log.warning(self.case1_curl["curl"][0])
        fun.cmd(self.case1_curl["curl"][0], 'c')
        re = fun.wait_data(self.case1_curl["curl"][1], 'c', self.case1_curl["curl"][2], '检查http请求', 100)
        assert self.case1_curl["curl"][2] in re
        log.warning('正常http请求发送成功')

        # 移除ACL策略
        fun.send(rbmExc,tool.interface().acl_interface(appId=tcp_appid, prototype='delAcl', content=self.case1_content),
                 rbmDomain, base_path)
        # 移除业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deltcp', Mode=0), rbmDomain,
                 base_path)
        log.warning('检查业务以及ACL是否删除成功：')
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) not in re


    @allure.feature('用例二：验证网络安全策略下发Bond接口动作执行为阻止的情况')
    def test_acl_ifname_bond_hold(self):
        log.warning('用例二：验证网络安全策略下发Bond接口动作执行为阻止的情况')
        # 设置为阻止
        self.case1_content['Action'] = 1
        # 下发业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addtcp', Mode=0), rbmDomain, base_path)
        # 下发ACL策略
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case1_content), rbmDomain, base_path)
        log.warning('检查策略是否下发成功：')
        re = fun.wait_data(type=6, dut='gw',context=str(self.case1_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) in re

        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case1_curl["curl"][2]}', 'c')
        log.warning('在客户端使用curl命令发送http请求验证联通性')
        log.warning(self.case1_curl["curl"][0])
        fun.cmd(self.case1_curl["curl"][0], 'c', thread=1, timeout=10)
        re = fun.wait_data(self.case1_curl["curl"][1], 'c', self.case1_curl["curl"][2], '检查http请求', 10, flag=False)
        assert '' == re
        log.warning('正常http请求发送失败')
        # 移除ACL策略
        fun.send(rbmExc,tool.interface().acl_interface(appId=tcp_appid, prototype='delAcl', content=self.case1_content),
                 rbmDomain, base_path)
        # 移除业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deltcp', Mode=0), rbmDomain,
                 base_path)
        log.warning('检查业务以及ACL是否删除成功：')
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) not in re


    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
