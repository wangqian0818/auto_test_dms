'''
脚本一：
用例名称：验证隔离下基于get+post+uri方法的网页访问策略的过滤
编写人员：李皖秋
编写日期：2021.7.9
测试目的：验证隔离下基于get+post+uri方法的网页访问策略的过滤
测试步骤：
1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来
2、下发http的get黑名单：test、juson；post黑名单：123、456；uri黑名单：mzh、hkl，等待nginx的24个进程起来
3、控制台发送get请求，不包含请求内容
4、控制台发送post请求，不包含请求内容
控制台发送get请求，请求内容包含get黑名单test
6、控制台发送get请求，请求内容包含get黑名单juson
7、控制台发送get请求，请求内容包含uri黑名单mzh
8、控制台发送get请求，请求内容包含uri黑名单hkl
9、控制台发送get请求，请求内容包含post黑名单123
10、控制台发送get请求，请求内容包含post黑名单456
11、控制台发送post请求，请求内容包含post黑名单123
12、控制台发送post请求，请求内容包含post黑名单456
13、控制台发送post请求，请求内容包含uri黑名单mzh
14、控制台发送post请求，请求内容包含uri黑名单hkl
15、控制台发送post请求，请求内容包含get黑名单test
16、控制台发送post请求，请求内容包含get黑名单juson
17、移除http的隔离策略，清空环境，等待nginx的24个进程起来
18、移除网页访问策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/http.json文件应该包含：c_get_args、c_post_args、c_http_uri和get黑名单参数：test、juson；post黑名单参数：123、456；uri黑名单参数：test、juson
3、请求成功，请求到的内容为server的index.html文件内包含的内容
4、请求成功，请求到的内容为server的index.html文件内包含的内容
5、请求失败，状态码返回为403
6、请求失败，状态码返回为403
7、请求失败，状态码返回为403
8、请求失败，状态码返回为403
9、请求成功，请求到的内容为server的index.html文件内包含的内容
10、请求成功，请求到的内容为server的index.html文件内包含的内容
11、请求失败，状态码返回为403
12、请求失败，状态码返回为403
13、请求失败，状态码返回为403
14、请求失败，状态码返回为403
15、请求成功，请求到的内容为server的index.html文件内包含的内容
16、请求成功，请求到的内容为server的index.html文件内包含的内容
17、cat /etc/jsac/http.stream应该不包含代理ip和port
18、cat /etc/jsac/http.json文件应该不包含：http协议
'''
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
    from Case_rbm.iso_http_check_get_post_uri import index
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

FrontDomain = baseinfo.BG8010FrontDomain

proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
url = index.proxy_url
http_content = baseinfo.http_content
http_ruleid = baseinfo.http_ruleid


class Test_iso_http_check_get_post_uri():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')

    def teardown_method(self):
        clr_env.iso_teardown_met('http', base_path)
        clr_env.clear_datacheck('http', base_path)

        clr_env.iso_setup_class(dut='FrontDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        self.method = index.method
        self.uri = index.uri

        self.check_url1 = index.check_url1
        self.check_url2 = index.check_url2

        clr_env.iso_setup_class(dut='FrontDut')

    @allure.feature('验证基于get+post+uri方法的网页访问策略的过滤')
    def test_iso_http_check_get_post_uri_a1(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='http')

        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', method=self.method, uri_data=self.uri),
                 FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查http应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='FrontDut', context=http_ruleid)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) in re

        time.sleep(3)
        # 1、发送get请求，不包含黑名单内容的普通请求
        status_code = http_check.http_get(url)
        log.warning('1、get普通请求【{}】的请求内容为：{}'.format(url, content))
        assert status_code == http_content

        # 2、发送post请求，不包含黑名单内容的普通请求
        status_code = http_check.http_post(url)
        log.warning('2、post普通请求【{}】的请求内容为：{}'.format(url, content))
        assert status_code == http_content

        # 3、发送get请求，请求内容包含第一个get黑名单
        status_code = http_check.http_get(self.check_url1, flag=1)
        log.warning('3、get请求内容包含黑名单【{}】返回的状态码为：{}'.format(self.check_url1, status_code))
        assert status_code == 405

        # 4、发送get请求，请求内容包含第二个get黑名单
        status_code = http_check.http_get(self.check_url2, flag=1)
        log.warning('4、get请求内容包含黑名单【{}】返回的状态码为：{}'.format(self.check_url2, status_code))
        assert status_code == 405

        # 7、发送post请求，请求内容包含第一个post黑名单
        status_code = http_check.http_post(self.check_url1, flag=1)
        log.warning('post请求内容包含黑名单【{}】返回的状态码为：{}'.format(self.check_url1, status_code))
        assert status_code == 405

        # 8、发送post请求，请求内容包含第二个post黑名单
        status_code = http_check.http_post(self.check_url2, flag=1)
        log.warning('6、post请求内容包含黑名单【{}】返回的状态码为：{}'.format(self.check_url2, status_code))
        assert status_code == 405

        log.warning('清空http传输策略')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查http安全浏览策略是否清空')
        re = fun.wait_data(type=4, dut='FrontDut', context=http_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) not in re

        log.warning('移除代理策略，清空环境')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        log.warning('检查代理策略是否移除成功')
        fun.check_proxy_policy(dut='FrontDut', type='http', flag=False)

    def teardown_class(self):
        # 回收环境
        clr_env.iso_setup_class(dut='FrontDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')

