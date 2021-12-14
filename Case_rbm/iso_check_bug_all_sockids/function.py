# encoding='utf-8'
from data_check import con_ftp, http_check

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
    from Case_rbm.iso_check_bug_all_sockids import index
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

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
http_url = index.http_url
http_content = baseinfo.http_content


class Test_iso_http_basic():

    # def setup_method(self):
    #     clr_env.data_check_setup_met(dut='FrontDut')
    #     clr_env.data_check_setup_met(dut='BackDut')
    #
    # def teardown_method(self):
    #     clr_env.iso_setup_class(dut='FrontDut')
    #     clr_env.iso_setup_class(dut='BackDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        fun.ssh_BG8010Server.connect()
        fun.ssh_BG8010Client.connect()
        #
        # clr_env.iso_setup_class(dut='FrontDut')
        # clr_env.iso_setup_class(dut='BackDut')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的使用http代理策略占满通道')
    def test_iso_all(self):
        # # 下发ftp隔离代理
        # fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp_front', appId=300), FrontDomain, base_path)
        # fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        # add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        # assert add_res1 == 1
        # # 登录ftp服务器，用户为白名单用户
        # log.warning(
        #     'proxy_ip：{}, baseinfo.ftp_proxy_port：{}, baseinfo.ftp_user：{}, baseinfo.ftp_pass：{}'.format(proxy_ip,
        #                                                                                                  baseinfo.ftp_proxy_port,
        #                                                                                                  baseinfo.ftp_user,
        #                                                                                                  baseinfo.ftp_pass))
        # fp = con_ftp.connect_ftp(proxy_ip, baseinfo.ftp_proxy_port, baseinfo.ftp_user, baseinfo.ftp_pass)
        # log.warning('ftp白名单欢迎语是：{}'.format(fp.getwelcome()))
        # assert '220' in fp.getwelcome()

        # 重复下发http代理策略，每条策略的appid、代理端口和目的端口不能一致
        for i in range(26):
            # time.sleep(3)
            proxy_port = 2280 + i
            proxy = proxy_ip + ':' + str(proxy_port)
            # 下发配置
            fun.send(rbmExc,
                     tool.interface().setAccessconf(prototype='addhttp_front', appId=i + 1, proxy_port=proxy_port,
                                                    server_port=80 + i), FrontDomain, base_path)
            fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
            front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
            assert front_res == 1
            # # 检查代理策略是否下发成功
            # re = fun.wait_data(type=1, dut='FrontDut', context=proxy)
            # assert proxy in re

            # # 发送get请求，验证隔离下的http策略
            # url = 'http://' + proxy
            # log.warning('请求地址为{}'.format(url))
            # content = http_check.http_get(url)
            # log.warning('验证隔离下的http策略请求内容为：{}'.format(content))
            # assert content == http_content

            # 移除策略，清空环境
            # time.sleep(3)
            # fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front', appId=i + 1),
            #          FrontDomain, base_path)
            # fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
            # fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
            # assert fdel_res == 1
            # fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
            # bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
            # assert bdel_res == 1

            # # 检查代理策略是否移除成功
            # proxy = proxy_ip + ':' + str(proxy_port)
            # re = fun.wait_data(type=1, dut='FrontDut', context=proxy)
            # assert proxy not in re

        # 移除ftp隔离代理
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp_front', appId=300), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res1 == 1
    #
    # def teardown_class(self):
    #     # 回收环境
    #     clr_env.iso_teardown_met('http', base_path)
    #     clr_env.iso_setup_class(dut='FrontDut')
    #     clr_env.iso_setup_class(dut='BackDut')
    #
    #     fun.rbm_close()
    #     fun.ssh_close('FrontDut')
    #
