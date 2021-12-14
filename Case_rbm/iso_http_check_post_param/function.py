'''
脚本一：
用例名称：验证隔离下基于post方法的网页访问策略的过滤
编写人员：李皖秋
编写日期：2021.7.7
测试目的：验证隔离下基于post方法的网页访问策略的过滤
测试步骤：
1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来
2、下发http的post黑名单，参数为：123，等待nginx的24个进程起来
3、控制台发送post请求，不包含请求内容
4、控制台发送post请求，请求内容不包含黑名单
5、控制台发送post请求，请求内容包含黑名单
6、移除http的隔离策略，清空环境，等待nginx的24个进程起来
7、移除网页访问策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/http.json文件应该包含：c_post_args和post黑名单参数：123
3、请求成功，请求到的内容为server的index.html文件内包含的内容
4、请求成功，请求到的内容为server的index.html文件内包含的内容
5、请求失败，状态码返回为403
6、cat /etc/jsac/http.stream应该不包含代理ip和port
7、cat /etc/jsac/http.json文件应该不包含：http协议

脚本二：
用例名称：验证隔离下基于post方法的多个网页访问策略的过滤
编写人员：李皖秋
编写日期：2021.7.8
测试目的：验证隔离下基于post方法的多个网页访问策略的过滤
测试步骤：
1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来
2、下发多个http的post黑名单，参数1为：test，参数2为juson，等待nginx的24个进程起来
3、控制台发送post请求，不包含请求内容
4、控制台发送post请求，请求内容不包含黑名单
5、控制台发送post请求，请求内容包含黑名单test
6、控制台发送post请求，请求内容包含黑名单juson
7、移除http的隔离策略，清空环境，等待nginx的24个进程起来
8、移除网页访问策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/http.json文件应该包含：c_post_args和post黑名单参数：test和juson
3、请求成功，请求到的内容为server的index.html文件内包含的内容
4、请求成功，请求到的内容为server的index.html文件内包含的内容
5、请求失败，状态码返回为403
6、请求失败，状态码返回为403
7、cat /etc/jsac/http.stream应该不包含代理ip和port
8、cat /etc/jsac/http.json文件应该不包含：http协议
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
    from Case_rbm.iso_http_check_post_param import index
    from common import fun, tool
    import common.ssh as c_ssh
except Exception as err:
    log.warning(
        '导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误
# import index
# del sys.path[0]
# dir_dir_path=os.path.abspath(os.path.join(os.getcwd()))
# sys.path.append(os.getcwd())

from common import baseinfo
from common import clr_env
from common.rabbitmq import *
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain

proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
url = index.url
http_content = baseinfo.http_content
http_ruleid = baseinfo.http_ruleid


class Test_iso_http_check_post():

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
        self.case1_parameter = index.case1_parameter
        self.check1_url1 = index.check1_url1
        self.case2_parameter = index.case2_parameter
        self.check2_url1 = index.check2_url1
        self.check2_url2 = index.check2_url2
        self.check_url = index.check_url

        # clr_env.iso_setup_class(dut='FrontDut')
        # clr_env.iso_setup_class(dut='BackDut')

    @allure.feature('验证基于post方法的网页访问策略的过滤')
    def test_iso_http_check_post_a1(self):
        # 下发配置
        log.warning('下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来;')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        log.warning('预期netstat -anp |grep tcp应该可以查看到监听ip和端口')
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut')

        # 下发数据结构检查策略
        log.warning('下发http数据结构检查策略')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', parameter=self.case1_parameter,
                                                        method=self.method), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查网页应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='FrontDut', context=http_ruleid)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) in re

        # 发送post请求，不包含黑名单内容的普通请求
        content = http_check.http_post(url)
        log.warning('post普通请求的请求【{}】内容为：{}'.format(url,content))
        assert content == http_content

        # 发送post请求，请求内容不包含黑名单内容
        status = http_check.http_post(self.check_url, flag=1)
        log.warning('post请求内容不包含黑名单的请求【{}】应返回的状态码为：{}'.format(self.check_url, status))
        assert status == 200

        # 发送post请求，请求内容包含黑名单
        status_code = http_check.http_post(self.check1_url1, flag=1)
        log.warning('post请求内容包含黑名单【{}】返回的状态码为：{}'.format(self.check1_url1, status_code))
        assert status_code == 405

        # 检查网页访问策略是否清空
        log.warning('移除网页访问策略')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查网页安全浏览策略是否清空')
        re = fun.wait_data(type=3, dut='FrontDut', context=http_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) not in re

        # 移除策略，还原环境
        log.warning('移除代理策略，清空环境')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1

        log.warning('检查代理策略是否移除成功')
        fun.check_proxy_policy(dut='FrontDut', flag=False)

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于post方法的多个网页访问策略的过滤')
    def test_iso_http_check_post_a2(self):
        # 下发配置
        log.warning('下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来;')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut')

        # 下发数据结构检查策略
        log.warning('下发http数据结构检查策略')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', parameter=self.case2_parameter,
                                                        method=self.method), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查网页应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='FrontDut', context=http_ruleid)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) in re

        # 发送post请求，不包含黑名单内容的普通请求
        content = http_check.http_post(url)
        log.warning('多个黑名单时post普通请求的请求内容为：{}'.format(content))
        assert content == http_content

        # 发送post请求，请求内容不包含黑名单内容
        status_code = http_check.http_post(self.check_url, flag=1)
        log.warning('多个黑名单时post请求内容不包含黑名单的请求【{}】应返回的状态码为：{}'.format(self.check_url, status_code))
        assert status_code == 200

        # 发送post请求，请求内容包含第一个黑名单
        status_code = http_check.http_post(self.check2_url1, flag=1)
        log.warning('多个黑名单时post请求内容包含第一个黑名单【{}】返回的状态码为：{}'.format(self.check2_url1, status_code))
        assert status_code == 405

        # 发送post请求，请求内容包含第二个黑名单
        status_code = http_check.http_post(self.check2_url2, flag=1)
        log.warning('多个黑名单时post请求内容包含第二个黑名单【{}】返回的状态码为：{}'.format(self.check2_url2, status_code))
        assert status_code == 405

        # 检查网页访问策略是否清空
        log.warning('移除网页访问策略，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该不包含：http的ruleid')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查网页安全浏览策略是否清空')
        re = fun.wait_data(type=3, dut='FrontDut', context=http_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) not in re

        # 移除策略，还原环境
        log.warning('移除代理策略，清空环境，等待nginx的24个进程起来;netstat -anp |grep tcp应该查看不到监听ip和端口')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='FrontDut', flag=False)

    # def teardown_class(self):
    #     # 回收环境
    #     clr_env.iso_setup_class(dut='FrontDut')
    #     clr_env.iso_setup_class(dut='BackDut')
    #
    #     fun.rbm_close()
    #     fun.ssh_close('FrontDut')
    #
