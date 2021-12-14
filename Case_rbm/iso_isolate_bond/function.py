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
    from Case_rbm.iso_isolate_bond import index
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
rbmExc = baseinfo.rbmExc
proxy_ip = baseinfo.BG8010FrontBondIp
front_ifname = baseinfo.BG8010["front_dut", "operationBond"]

class Test_iso_isolate_bond():

    def setup_class(self):
        # 获取参数
        fun.ssh_c.connect()
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        self.http_url1 = index.http_url1
        self.case1_gapFromTo = index.case1_gapFromTo
        clr_env.iso_setup_class(dut='FrontDut')


    @allure.feature('用例一：验证隔离设备的bond口的通信情况')
    def test_iso_isolate_bond(self):
        # 下发配置
        log.warning('用例一：验证隔离设备的bond口的通信情况')
        fun.send(rbmExc, tool.interface().setAccessconf(proxy_ip=proxy_ip,prototype='addhttp_front', GapFromTo=self.case1_gapFromTo), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', p_ip=proxy_ip)

        # 发送get请求，验证隔离下的http策略
        log.warning('请求地址为{}'.format(self.http_url1))
        http_code = http_check.http_get(self.http_url1, flag=1)
        log.warning('验证隔离下的http策略请求返回状态码为：{}'.format(http_code))
        assert http_code == 200

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', p_ip=proxy_ip, flag=False)

    def teardown_class(self):
        # 回收环境
        clr_env.iso_teardown_met('http', base_path)
        clr_env.iso_teardown_met('http_post', base_path)
        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')
        fun.rbm_close()
        fun.ssh_close('FrontDut')

