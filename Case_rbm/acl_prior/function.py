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
    from Case_rbm.acl_prior import index
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

class Test_acl_prior():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env
        self.case1_content = index.case1_content
        self.case2_content = index.case2_content
        self.case3_content = index.case3_content
        self.case_curl = index.case_curl
        clr_env.clear_env()


    @allure.feature('用例一：验证网络安全策略优先级（允许的优先级等于阻止的优先级）的情况（期望阻止大允许）')
    def test_acl_ifname_bond_allow_eq_hold(self):
        log.warning('用例一：验证网络安全策略优先级（允许的优先级等于阻止的优先级）的情况')
        # 下发业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addtcp', Mode=0), rbmDomain, base_path)
        # 下发ACL策略-动作为允许
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case1_content), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', context=str(self.case1_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) in re

        # 下发ACL策略-动作为阻止
        self.case1_content['Action'] = 1
        self.case1_content['Dport'] = ''
        self.case1_content['RuleId'] = self.case1_content['RuleId'] + 1
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case1_content), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', context=str(self.case1_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) in re
        # RuleId上一步加1，此时需要重置减1
        self.case1_content['RuleId'] = self.case1_content['RuleId'] - 1

        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case_curl["curl"][2]}', 'c')
        log.warning('在客户端使用curl命令发送http请求验证联通性')
        log.warning(self.case_curl["curl"][0])
        fun.cmd(self.case_curl["curl"][0], 'c', thread=1, timeout=10)
        time.sleep(10)
        re = fun.wait_data(self.case_curl["curl"][1], 'c', self.case_curl["curl"][2], '检查http请求', 100, flag=False)
        assert '' == re
        log.warning('正常http请求发送失败')

        # 移除ACL策略
        fun.send(rbmExc,tool.interface().acl_interface(appId=tcp_appid, prototype='delAcl'), rbmDomain, base_path)
        # 移除业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deltcp', Mode=0), rbmDomain, base_path)
        log.warning('检查业务以及ACL是否删除成功：')
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) not in re and str(self.case1_content['RuleId']+1) not in re


    @allure.feature('用例二：验证网络安全策略优先级（允许优先级大于阻止优先级）的情况（期望允许大于阻止）')
    def test_acl_ifname_bond_allow_gt_hold(self):
        log.warning('用例二：验证网络安全策略优先级（允许优先级大于阻止优先级）的情况')
        # 下发业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addtcp', Mode=0), rbmDomain, base_path)
        # 下发ACL策略-动作为允许
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case2_content), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', context=str(self.case2_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case2_content['RuleId']) in re

        # 下发ACL策略-动作为阻止
        self.case2_content['Action'] = 1
        self.case2_content['Dport'] = ''
        self.case2_content['Listorder'] = 1
        self.case2_content['RuleId'] = self.case2_content['RuleId'] + 1
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case2_content), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', context=str(self.case2_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case2_content['RuleId']) in re
        # RuleId上一步加1，此时需要重置减1
        self.case2_content['RuleId'] = self.case2_content['RuleId'] - 1
        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case_curl["curl"][2]}', 'c')
        log.warning('在客户端使用curl命令发送http请求验证联通性')
        log.warning(self.case_curl["curl"][0])
        fun.cmd(self.case_curl["curl"][0], 'c')
        re = fun.wait_data(self.case_curl["curl"][1], 'c', self.case_curl["curl"][2], '检查http请求', 100)
        assert self.case_curl["curl"][2] in re
        log.warning('正常http请求发送成功')
        # 移除ACL策略
        fun.send(rbmExc,tool.interface().acl_interface(appId=tcp_appid, prototype='delAcl'), rbmDomain, base_path)
        # 移除业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deltcp', Mode=0), rbmDomain, base_path)
        log.warning('检查业务以及ACL是否删除成功：')
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case2_content['RuleId']) not in re and str(self.case2_content['RuleId']+1) not in re

    @allure.feature('用例三：验证网络安全策略优先级（允许优先级小于阻止优先级）的情况（期望允许小于阻止）')
    def test_acl_ifname_bond_allow_lt_hold(self):
        log.warning('用例三：验证网络安全策略优先级（允许优先级小于阻止优先级）的情况')
        # 下发业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addtcp', Mode=0), rbmDomain, base_path)
        # 下发ACL策略-动作为允许
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case3_content), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', context=str(self.case3_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case3_content['RuleId']) in re

        # 下发ACL策略-动作为阻止
        self.case3_content['Action'] = 1
        self.case3_content['Dport'] = ''
        self.case3_content['Listorder'] = 3
        self.case3_content['RuleId'] = self.case3_content['RuleId'] + 1
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case3_content), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', context=str(self.case3_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case3_content['RuleId']) in re
        # RuleId上一步加1，此时需要重置减1
        self.case3_content['RuleId'] = self.case3_content['RuleId'] - 1
        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case_curl["curl"][2]}', 'c')
        log.warning('在客户端使用curl命令发送http请求验证联通性')
        log.warning(self.case_curl["curl"][0])
        fun.cmd(self.case_curl["curl"][0], 'c', thread=1, timeout=10)
        time.sleep(10)
        re = fun.wait_data(self.case_curl["curl"][1], 'c', self.case_curl["curl"][2], '检查http请求', 100, flag=False)
        assert '' == re
        log.warning('正常http请求发送失败')
        # 移除ACL策略
        fun.send(rbmExc,tool.interface().acl_interface(appId=tcp_appid, prototype='delAcl'), rbmDomain, base_path)
        # 移除业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deltcp', Mode=0), rbmDomain, base_path)
        log.warning('检查业务以及ACL是否删除成功：')
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case3_content['RuleId']) not in re and str(self.case3_content['RuleId']+1) not in re


    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
