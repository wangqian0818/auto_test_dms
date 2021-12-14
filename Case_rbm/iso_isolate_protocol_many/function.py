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
    from Case_rbm.iso_isolate_protocol_many import index
    from common import fun, tool, clr_env
    import common.ssh as c_ssh
    from data_check import con_ftp
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
udp_appid = baseinfo.udp_appid
http_proxy_port = baseinfo.http_proxy_port
http_server_port = baseinfo.http_server_port

ftp_appid = baseinfo.ftp_appid


ftp_proxy_port = baseinfo.ftp_proxy_port
ftp_user = baseinfo.ftp_user
ftp_pass = baseinfo.ftp_pass

ftp2_ip = index.ftp2_ip
ftp2_user = index.ftp2_user
ftp2_pass = index.ftp2_pass

class Test_iso_isolate_protocol_many():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')

    def teardown_method(self):
        clr_env.iso_setup_class(dut='FrontDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_c.connect()
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        fun.ssh_BG8010Server.connect()
        fun.ssh_BG8010Client.connect()
        self.http_url1 = index.http_url1
        self.http_url2 = index.http_url2

        self.udp_url1 = index.udp_url1
        self.udp_url2 = index.udp_url2
        clr_env.iso_setup_class(dut='FrontDut')

    @allure.feature('用例一：验证隔离设备tcp通信协议下的多条策略下发情况')
    def test_iso_isolate_tcp_two(self):
        # 下发配置
        log.warning('用例一：验证隔离设备tcp通信协议下的多条策略下发情况')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addtcp_iso', Mode=2), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='tcp')

        http_appid2 = http_appid+10
        server_port2 = http_server_port+1
        proxy_port2 = http_proxy_port + 1
        fun.send(rbmExc, tool.interface().setAccessconf(appId=http_appid2, server_port=server_port2, proxy_port=proxy_port2, prototype='addtcp_iso', Mode=2), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(appid=http_appid2, p_port=proxy_port2, dut='FrontDut', type='tcp')

        # 发送get请求，验证隔离下的http策略
        log.warning('请求地址为{}'.format(self.http_url1))
        http_code = http_check.http_get(self.http_url1, flag=1)
        log.warning('验证隔离下的http策略请求返回状态码为：{}'.format(http_code))
        assert http_code == 200

        # 发送get请求，验证隔离下的http策略
        log.warning('请求地址为{}'.format(self.http_url2))
        http_code = http_check.http_get(self.http_url2, flag=1)
        log.warning('验证隔离下的http策略请求返回状态码为：{}'.format(http_code))
        assert http_code == 200

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='deltcp', Mode=2), FrontDomain, base_path)
        time.sleep(1)
        fun.send(rbmExc, tool.interface().setAccessconf(appId=http_appid2, prototype='deltcp', Mode=2), FrontDomain, base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', flag=False, type='tcp')
        fun.check_proxy_policy(appid=http_appid2, p_port=proxy_port2, dut='FrontDut', flag=False, type='tcp')

    @allure.feature('用例二：验证隔离设备http通信协议下的多条策略下发情况')
    def test_iso_isolate_http_two(self):
        # 下发配置
        log.warning('用例二：验证隔离设备http通信协议下的多条策略下发情况')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut')

        http_appid2 = http_appid + 10
        server_port2 = http_server_port + 1
        proxy_port2 = http_proxy_port + 1
        fun.send(rbmExc,tool.interface().setAccessconf(appId=http_appid2, server_port=server_port2, proxy_port=proxy_port2,
                                                prototype='addhttp_front'), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(appid=http_appid2, p_port=proxy_port2, dut='FrontDut')

        # 发送get请求，验证隔离下的http策略
        log.warning('请求地址为{}'.format(self.http_url1))
        http_code = http_check.http_get(self.http_url1, flag=1)
        log.warning('验证隔离下的http策略请求返回状态码为：{}'.format(http_code))
        assert http_code == 200

        # 发送get请求，验证隔离下的http策略
        log.warning('请求地址为{}'.format(self.http_url2))
        http_code = http_check.http_get(self.http_url2, flag=1)
        log.warning('验证隔离下的http策略请求返回状态码为：{}'.format(http_code))
        assert http_code == 200

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        time.sleep(1)
        fun.send(rbmExc, tool.interface().setAccessconf(appId=http_appid2, prototype='delhttp_front'), FrontDomain,
                 base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', flag=False)
        fun.check_proxy_policy(appid=http_appid2, p_port=proxy_port2, dut='FrontDut', flag=False)


    @allure.feature('用例三：验证隔离设备udp通信协议下的多条策略下发情况')
    def test_iso_isolate_udp_two(self):
        # 下发配置
        log.warning('用例三：验证隔离设备udp通信协议下的多条策略下发情况')
        fun.send(rbmExc, tool.interface().setAccessconf(appId=udp_appid, prototype='addudp_iso', Mode=2, L4protocol='udp'), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(appid=udp_appid, dut='FrontDut', type='udp')

        udp_appid2 = udp_appid+10
        server_port2 = http_server_port+1
        proxy_port2 = http_proxy_port + 1
        fun.send(rbmExc, tool.interface().setAccessconf(appId=udp_appid2, server_port=server_port2, proxy_port=proxy_port2, prototype='addudp_iso', Mode=2, L4protocol='udp'), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(appid=udp_appid2, p_port=proxy_port2, dut='FrontDut', type='udp')

        fun.cmd("rm -f /opt/pkt/iso_udp*.txt", 'c')
        # 客户端发送http请求
        log.warning('在客户端使用命令发送udp请求验证联通性')
        log.warning(self.udp_url1["curl"][0])
        fun.cmd(self.udp_url1["curl"][0], 'c')
        re = fun.wait_data(self.udp_url1["curl"][1], 'c', self.udp_url1["curl"][2], '检查udp请求', 100)
        assert self.udp_url1["curl"][2] in re
        log.warning('正常udp请求发送成功')
        log.warning('在客户端使用命令发送udp请求验证联通性')
        log.warning(self.udp_url2["curl"][0])
        fun.cmd(self.udp_url2["curl"][0], 'c')
        re = fun.wait_data(self.udp_url2["curl"][1], 'c', self.udp_url2["curl"][2], '检查udp请求', 100)
        assert self.udp_url2["curl"][2] in re
        log.warning('正常udp请求发送成功')

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(appId=udp_appid, prototype='deludp', Mode=2, L4protocol='udp'), FrontDomain, base_path)
        time.sleep(1)
        fun.send(rbmExc, tool.interface().setAccessconf(appId=udp_appid2, prototype='deludp', Mode=2, L4protocol='udp'), FrontDomain, base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(appid=udp_appid, dut='FrontDut', flag=False, type='udp')
        fun.check_proxy_policy(appid=udp_appid2, p_port=proxy_port2, dut='FrontDut', flag=False, type='udp')


    @allure.feature('用例四：验证隔离设备ftp通信协议下的多条策略下发情况')
    def test_iso_isolate_ftp_two(self):
        # 下发配置
        log.warning('用例四：验证隔离设备ftp通信协议下的多条策略下发情况')
        fun.send(rbmExc, tool.interface().ftp_agent(prototype='addftp_front'), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='ftp')

        ftp2_appid = ftp_appid + 10
        ftp2_proxy_port = ftp_proxy_port + 1
        fun.send(rbmExc, tool.interface().ftp_agent(appId=ftp2_appid, dip=ftp2_ip, proxy_port=ftp2_proxy_port,prototype='addhttp_front'), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(appid=ftp2_appid, p_port=ftp2_proxy_port, dut='FrontDut', type='ftp')


        fp = con_ftp.connect_ftp(proxy_ip, ftp_proxy_port, ftp_user, ftp_pass)
        log.warning('ftp1欢迎语是：{}'.format(fp.getwelcome()))

        fp = con_ftp.connect_ftp(proxy_ip, ftp_proxy_port, ftp2_user, ftp2_pass)
        log.warning('ftp2欢迎语是：{}'.format(fp.getwelcome()))

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().ftp_agent(prototype='delftp_front'), FrontDomain, base_path)
        time.sleep(1)
        fun.send(rbmExc, tool.interface().ftp_agent(appId=ftp2_appid, prototype='delftp_front'), FrontDomain, base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='ftp', flag=False)
        fun.check_proxy_policy(appid=ftp2_appid, p_port=ftp2_proxy_port, dut='FrontDut', type='ftp', flag=False)

    @allure.feature('用例五：验证隔离设备tcp和udp同一个端口的策略下发情况')
    def test_iso_isolate_tcp_udp(self):
        # 下发配置
        log.warning('用例五：验证隔离设备tcp和udp同一个端口的策略下发情况')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addtcp_iso', Mode=2), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='tcp')

        fun.send(rbmExc, tool.interface().setAccessconf(appId=udp_appid, prototype='addudp_iso', Mode=2, L4protocol='udp'), FrontDomain, base_path)
        time.sleep(3)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(appid=udp_appid, dut='FrontDut', type='udp')

        # 发送get请求，验证隔离下的http策略
        log.warning('请求地址为{}'.format(self.http_url1))
        http_code = http_check.http_get(self.http_url1, flag=1)
        log.warning('验证隔离下的http策略请求返回状态码为：{}'.format(http_code))
        assert http_code == 200

        fun.cmd("rm -f /opt/pkt/iso_udp*.txt", 'c')
        # 客户端发送http请求
        log.warning('在客户端使用命令发送udp请求验证联通性')
        log.warning(self.udp_url1["curl"][0])
        fun.cmd(self.udp_url1["curl"][0], 'c')
        re = fun.wait_data(self.udp_url1["curl"][1], 'c', self.udp_url1["curl"][2], '检查udp请求', 100)
        assert self.udp_url1["curl"][2] in re

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='deltcp', Mode=2), FrontDomain, base_path)
        time.sleep(1)
        fun.send(rbmExc, tool.interface().setAccessconf(appId=udp_appid, prototype='deludp', Mode=2, L4protocol='udp'), FrontDomain, base_path)
        time.sleep(1)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', flag=False, type='tcp')
        fun.check_proxy_policy(appid=udp_appid, dut='FrontDut', flag=False, type='udp')

    def teardown_class(self):
        # 回收环境
        clr_env.iso_teardown_met('http', base_path)
        clr_env.iso_teardown_met('http_post', base_path)
        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')
        fun.rbm_close()
        fun.ssh_close('FrontDut')

