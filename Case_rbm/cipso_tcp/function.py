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
    from Case_rbm.cipso_tcp import index
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
gwClientIp = baseinfo.gwClientIp
clientOpeIp = baseinfo.clientOpeIp
serverOpeIp = baseinfo.serverOpeIp


class Test_cipso_tcp():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env
        self.cipso_doi = index.cipso_doi
        self.case1_mtLabel = index.case1_mtLabel
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        clr_env.clear_env()


    @allure.feature('用例一：验证标记对tcp报文的完整通信')
    def test_cipso_tcp_double(self):
        log.warning('用例一：验证标记对tcp报文的完整通信')
        # 1.设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case1_mtLabel)

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

        # 3.客户端发送http请求
        log.warning('在客户端使用curl命令发送http请求验证联通性')
        log.warning(self.cipso_doi["curl"][0])
        fun.cmd(self.cipso_doi["curl"][0], 'c')
        re = fun.wait_data(self.cipso_doi["curl"][1], 'c', self.cipso_doi["curl"][2], '检查http请求', 100)
        assert self.cipso_doi["curl"][2] in re
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

        # 5.删除/opt/cipso_curl.txt文件
        log.warning('在客户端rm -f /opt/cipso*.txt删除第3步http请求结果的文件cipso*.txt，ls /opt/ |grep txt查询不到cipso_curl_doi.txt说明文件删除成功')
        fun.cmd("rm -f /opt/cipso*.txt", 'c')
        re = fun.cmd("ls /opt/ |grep txt", 'c')
        log.warning('客户端txt文件查询结果是:{}'.format(re))
        assert self.cipso_doi["txt"][0] not in re

        # 6.设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case1_mtLabel)


    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
