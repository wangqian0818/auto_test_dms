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
    from Case_rbm.acl_cipso import index
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

class Test_acl_cipso():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env
        self.case1_content = index.case1_content
        self.case1_mtLabel = index.case1_mtLabel
        self.case_curl = index.case_curl
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        clr_env.clear_env()


    @allure.feature('用例一：验证网络安全策略协议为TCP、动作执行为允许的情况（设备下发标记）')
    def test_acl_tcp_allow_cipso(self):
        log.warning('用例一：验证网络安全策略协议为TCP、动作执行为允许的情况（设备下发标记）')
        # 下发业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='addtcp', Mode=0), rbmDomain, base_path)
        # 下发安全标记策略
        fun.send(rbmExc, tool.interface().cipso_selabel_interface(appId=tcp_appid, prototype='addSelabel',
                                                                  mtLabel=self.case1_mtLabel),
                 rbmDomain, base_path)
        # 检查安全标记策略是否下发成功
        log.warning('检查设备安全标记策略是否下发成功：')
        mtLabelStr = fun.change_check_labelStr(self.case1_mtLabel)
        log.warning(mtLabelStr)
        re = fun.wait_data(type=6, dut='gw', context=mtLabelStr, number=100)
        log.warning('预期包含内容：{}'.format(mtLabelStr))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert mtLabelStr in re
        # 下发ACL策略-动作为允许
        fun.send(rbmExc, tool.interface().acl_interface(appId=tcp_appid, prototype='addAcl', content=self.case1_content), rbmDomain, base_path)
        log.warning('检查设备ACL策略是否下发成功：')
        # re = fun.wait_data(command='export cardid=1&&tupleacl --get', dut='gw', context=str(self.case1_content['RuleId']), number=100)
        re = fun.wait_data(type=6, dut='gw', context=str(self.case1_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) in re

        # 客户端和服务端iptables初始化
        log.warning('客户端和服务端iptables初始化')
        while True:
            re = fun.wait_data(type=7, dut='c')
            log.warning(re)
            if self.case1_step2["step1"][1] not in re:
                break
            fun.cmd(self.case1_step2["step1"][0], 'c')
        while True:
            re = fun.wait_data(type=7, dut='s')
            log.warning(re)
            if self.case1_step2["step2"][1] not in re:
                break
            fun.cmd(self.case1_step2["step2"][0], 's')
        # 客户端通过ssh下发配置并检查结果
        log.warning('客户端下发管理口标记策略')
        fun.cmd(self.case1_step1["step1"][0], 'c')
        re = fun.wait_data(type=7, dut='c', context=self.case1_step1["step1"][1], number=10)
        log.warning('预期包含内容：{}'.format(self.case1_step1["step1"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case1_step1["step2"][1] in re
        # 服务端通过ssh下发配置并检查结果
        log.warning('服务端通过ssh下发配置并检查结果')
        fun.cmd(self.case1_step1["step2"][0], 's')
        re = fun.wait_data(type=7, dut='s', context=self.case1_step1["step2"][1], number=100)
        log.warning('预期包含内容：{}'.format(self.case1_step1["step2"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case1_step1["step2"][1] in re


        # 客户端发送http请求
        fun.cmd(f'rm -rf /opt/pkt/{self.case_curl["curl"][2]}', 'c')
        log.warning('在客户端使用curl命令发送http请求验证联通性')
        log.warning(self.case_curl["curl"][0])
        fun.cmd(self.case_curl["curl"][0], 'c')
        re = fun.wait_data(self.case_curl["curl"][1], 'c', self.case_curl["curl"][2], '检查http请求', 100)
        assert self.case_curl["curl"][2] in re
        log.warning('正常http请求发送成功')


        # 客户端移除管理口标记策略
        log.warning('客户端移除管理口标记策略')
        fun.cmd(self.case1_step2["step1"][0], 'c')
        re = fun.wait_data(type=7, dut='c', context=self.case1_step2["step1"][1], number=1, flag=False)
        log.warning('预期包含内容：{}'.format(self.case1_step2["step1"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case1_step2["step1"][1] not in re

        # 服务端移除管理口标记策略
        log.warning('服务端移除管理口标记策略')
        log.warning(self.case1_step2["step2"][0])
        fun.cmd(self.case1_step2["step2"][0], 's')
        re = fun.wait_data(type=7, dut='s', context=self.case1_step2["step2"][1], number=1, flag=False)
        log.warning('预期包含内容：{}'.format(self.case1_step2["step2"][1]))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert self.case1_step2["step2"][1] not in re


        # 移除ACL策略
        fun.send(rbmExc,tool.interface().acl_interface(appId=tcp_appid, prototype='delAcl'), rbmDomain, base_path)
        # 设备移除策略
        log.warning('设备移除策略')
        fun.send(rbmExc, tool.interface().cipso_selabel_interface(appId=tcp_appid, prototype='delSelabel'), rbmDomain, base_path)
        re = fun.wait_data(type=6, dut='gw', context=mtLabelStr, number=100, flag=False)
        log.warning('预期包含内容：{}'.format(mtLabelStr))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert mtLabelStr not in re
        # 移除业务配置
        fun.send(rbmExc, tool.interface().tcp_udp_interface(appId=tcp_appid, prototype='deltcp', Mode=0), rbmDomain, base_path)
        log.warning('检查业务以及ACL是否删除成功：')
        re = fun.wait_data(type=6, dut='gw', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) not in re





    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
