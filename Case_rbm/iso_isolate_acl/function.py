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
    from Case_rbm.iso_isolate_acl import index
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
rbmExc = baseinfo.rbmExc
http_content = baseinfo.http_content
http_appid = baseinfo.http_appid
http_proxy_port = baseinfo.http_proxy_port
http_server_port = baseinfo.http_server_port

class Test_iso_isolate_acl():

    def setup_class(self):
        # 获取参数
        fun.ssh_c.connect()
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()

        self.http_url1 = index.http_url1
        self.case1_content = index.case1_content
        self.case2_content = index.case2_content
        clr_env.iso_setup_class(dut='FrontDut')


    @allure.feature('用例一：验证隔离设备的ACL策略通信情况（阻止和允许）')
    def test_iso_isolate_acl(self):
        # 下发配置
        log.warning('用例一：验证隔离设备的ACL策略通信情况（阻止和允许）')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut')

        # 下发ACL策略-动作为阻止
        log.warning('下发ACL策略-动作为阻止')
        self.case1_content['Action'] = 1
        log.warning(self.case1_content)
        fun.send(rbmExc, tool.interface().acl_interface(appId=http_appid, prototype='addAcl', content=self.case1_content), FrontDomain, base_path)
        re = fun.wait_data(type=6, dut='FrontDut', context=str(self.case1_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) in re
        # 发送get请求，验证隔离下的http策略
        log.warning('请求地址为{}'.format(self.http_url1))
        http_code = http_check.http_get(self.http_url1, flag=1)
        log.warning('验证隔离下的http策略请求返回状态码为：{}'.format(http_code))
        assert http_code == 200

        # 下发ACL策略-动作为允许
        log.warning('下发ACL策略-动作为允许')
        self.case1_content['Action'] = 0
        log.warning(self.case1_content)
        fun.send(rbmExc, tool.interface().acl_interface(appId=http_appid, prototype='addAcl', content=self.case1_content), FrontDomain, base_path)
        re = fun.wait_data(type=6, dut='FrontDut', context=str(self.case1_content['RuleId']), number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) in re

        # 发送get请求，验证隔离下的http策略
        log.warning('请求地址为{}'.format(self.http_url1))
        http_code = http_check.http_get(self.http_url1, flag=1)
        log.warning('验证隔离下的http策略请求返回状态码为：{}'.format(http_code))
        assert http_code == 200

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().acl_interface(appId=http_appid, prototype='delAcl'), FrontDomain, base_path)
        time.sleep(0.5)
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', flag=False)
        #检查ACL是否删除成功
        re = fun.wait_data(type=6, dut='FrontDut', number=100)
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert str(self.case1_content['RuleId']) not in re



    def teardown_class(self):
        # 回收环境
        clr_env.iso_teardown_met('http', base_path)
        clr_env.iso_teardown_met('http_post', base_path)
        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')
        fun.rbm_close()
        fun.ssh_close('FrontDut')

