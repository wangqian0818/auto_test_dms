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
    from Case_rbm.acl_agent import index
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

class Test_acl_agent():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        self.clr_env = clr_env
        self.case1_content = index.case1_content
        self.case_curl = index.case_curl
        clr_env.clear_env()

    @allure.feature('用例一：验证网络安全策略跟反向代理结合的情况')
    def test_acl_agent(self):
        log.warning('用例一：验证网络安全策略跟反向代理结合的情况')
        # 下发配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addtcp_proxy', Mode=2), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='gw', type='tcp')

        # 下发ACL策略-动作为阻止
        log.warning('下发ACL策略-动作为阻止')
        self.case1_content['Action'] = 1
        log.warning(self.case1_content)
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case1_content), rbmDomain, base_path)
        # re = fun.wait_data(command='export cardid=1&&tupleacl --get',  dut='gw', context=str(self.case1_content['RuleId']), number=100)
        re = fun.wait_data(type=6, dut='gw', context=str(self.case1_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) in re
        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case_curl["curl"][2]}', 'c')
        log.warning('在客户端使用curl命令发送http请求验证联通性')
        log.warning(self.case_curl["curl"][0])
        fun.cmd(self.case_curl["curl"][0], 'c', thread=1, timeout=10)
        time.sleep(10)
        re = fun.wait_data(self.case_curl["curl"][1], 'c', self.case_curl["curl"][2], '检查http请求', 100, flag=False)
        assert '' == re
        log.warning('正常http请求发送失败')

        # 下发ACL策略-动作为允许
        log.warning('修改ACL策略-动作为允许')
        self.case1_content['Action'] = 0
        log.warning(self.case1_content)
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case1_content), rbmDomain, base_path)
        log.warning('检查设备ACL策略是否下发成功：')
        # re = fun.wait_data(command='export cardid=1&&tupleacl --get', dut='gw', context=str(self.case1_content['RuleId']), number=100)
        re = fun.wait_data(type=6, dut='gw', context=str(self.case1_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) in re
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
        log.warning('检查ACL是否删除成功：')
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) not in re

        # 移除业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deltcp', Mode=0), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='gw', type='tcp', flag=False)



    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
