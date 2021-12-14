'''
脚本一：
用例名称：验证隔离下基于URI黑名单、get请求方法、post请求方法、MIME多种类型设置放行的网页访问策略
编写人员：李皖秋
编写日期：2021.7.12
测试目的：验证隔离下基于URI黑名单、get请求方法、post请求方法、MIME多种类型设置放行的网页访问策略
测试步骤：
1、下发http的隔离策略：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来
2、下发http的get黑名单，参数为：hello、juson；post黑名单：123、456；uri黑名单：mzh、hkl；MIME白名单：css、avi，等待nginx的24个进程起来
3、控制台发送get请求，不包含请求内容
4、控制台发送post请求，不包含请求内容
5、控制台发送get请求，请求内容包含get黑名单hello
6、控制台发送get请求，请求内容包含get黑名单juson
7、控制台发送get请求，请求内容包含uri黑名单mzh
8、控制台发送get请求，请求内容包含uri黑名单hkl
9、控制台发送get请求，请求内容包含post黑名单123
10、控制台发送get请求，请求内容包含post黑名单456
11、控制台发送post请求，请求内容包含post黑名单123
12、控制台发送post请求，请求内容包含post黑名单456
13、控制台发送post请求，请求内容包含uri黑名单mzh
14、控制台发送post请求，请求内容包含uri黑名单hkl
15、控制台发送post请求，请求内容包含get黑名单hello
16、控制台发送post请求，请求内容包含get黑名单juson
17、控制台发送get请求，请求内容包含MIME白名单css
18、控制台发送get请求，请求内容包含MIME白名单avi
19、控制台发送get请求，请求内容包含MIME类型但不在其白名单：pdf
20、控制台发送get请求，请求内容包含MIME白名单：css和get黑名单：juson
21、控制台发送get请求，请求内容包含MIME白名单：avi和post黑名单：123
22、移除http的隔离策略，清空环境，等待nginx的24个进程起来
23、移除网页访问策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/http.json文件应该包含：c_get_args、c_post_args、c_http_uri、s_content_type和get黑名单参数：test、juson；post黑名单参数：123、456；uri黑名单参数：test、juson；MIME白名单参数：css、avi
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
17、请求成功，状态码返回为200
18、请求成功，状态码返回为200
19、请求失败，状态码返回为403
20、请求失败，状态码返回为403
21、请求成功，状态码返回为200
22、cat /etc/jsac/http.stream应该不包含代理ip和port
23、cat /etc/jsac/http.json文件应该不包含：http协议

脚本二：
用例名称：验证隔离下基于URI黑名单、get请求方法、post请求方法、MIME多种类型设置阻断的网页访问策略
编写人员：李皖秋
编写日期：2021.7.13
测试目的：验证隔离下基于URI黑名单、get请求方法、post请求方法、MIME多种类型设置阻断的网页访问策略
测试步骤：
1、下发http的隔离策略：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来
2、下发http的get黑名单，参数为：hello、juson；post黑名单：123、456；uri黑名单：mzh、hkl；MIME黑名单：css、avi，等待nginx的24个进程起来
3、控制台发送get请求，不包含请求内容
4、控制台发送post请求，不包含请求内容
5、控制台发送get请求，请求内容包含get黑名单hello
6、控制台发送get请求，请求内容包含get黑名单juson
7、控制台发送get请求，请求内容包含uri黑名单mzh
8、控制台发送get请求，请求内容包含uri黑名单hkl
9、控制台发送get请求，请求内容包含post黑名单123
10、控制台发送get请求，请求内容包含post黑名单456
11、控制台发送post请求，请求内容包含post黑名单123
12、控制台发送post请求，请求内容包含post黑名单456
13、控制台发送post请求，请求内容包含uri黑名单mzh
14、控制台发送post请求，请求内容包含uri黑名单hkl
15、控制台发送post请求，请求内容包含get黑名单hello
16、控制台发送post请求，请求内容包含get黑名单juson
17、控制台发送get请求，请求内容包含MIME黑名单css
18、控制台发送get请求，请求内容包含MIME黑名单avi
19、控制台发送get请求，请求内容包含MIME类型但不在黑白名单：pdf
20、控制台发送get请求，请求内容包含MIME黑名单：avi和post黑名单：123
21、控制台发送get请求，请求内容包含MIME类型但不在黑名单：pdf和get黑名单：hello
22、移除http的隔离策略，清空环境，等待nginx的24个进程起来
23、移除网页访问策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/http.json文件应该包含：c_get_args、c_post_args、c_http_uri、s_content_type和get黑名单参数：test、juson；post黑名单参数：123、456；uri黑名单参数：test、juson；MIME白名单参数：css、avi
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
17、请求失败，状态码返回为403
18、请求失败，状态码返回为403
19、请求成功，状态码返回为200
20、请求失败，状态码返回为403
21、请求失败，状态码返回为403
22、cat /etc/jsac/http.stream应该不包含代理ip和port
23、cat /etc/jsac/http.json文件应该不包含：http协议
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
    from Case_rbm.iso_http_check_get_post_uri_MIME import index
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
http_url = index.http_url
http_content = baseinfo.http_content


class Test_iso_http_check_get_post_uri_MIME():

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
        self.case1_step1 = index.case1_step1
        self.case1_step11 = index.case1_step11
        self.case1_step2 = index.case1_step2
        self.case2_step2 = index.case2_step2
        self.delcheck = index.delcheck
        self.data = index.data
        self.case1_get_data1 = index.case1_get_data1
        self.case1_get_data2 = index.case1_get_data2
        self.case1_post_data1 = index.case1_post_data1
        self.case1_post_data2 = index.case1_post_data2
        self.case1_uri1 = index.case1_uri1
        self.case1_uri2 = index.case1_uri2
        self.case1_MIME1 = index.case1_MIME1
        self.case1_MIME2 = index.case1_MIME2
        self.base_uri = index.base_uri

        self.get1_data1 = index.get1_data1
        self.get1_data2 = index.get1_data2
        self.post1_data1 = index.post1_data1
        self.post1_data2 = index.post1_data2
        self.check1_uri1 = index.check1_uri1
        self.check1_uri2 = index.check1_uri2
        self.MIME1_uri1 = index.MIME1_uri1
        self.MIME1_uri2 = index.MIME1_uri2

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下基于URI黑名单、get请求方法、post请求方法、MIME多种类型设置放行的网页访问策略')
    def test_iso_http_check_get_post_uri_MIME_a1(self):
        # 下发配置
        log.warning('1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来;预期netstat -anp |grep tcp应该可以查看到监听ip和端口')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step11[key][1] in re

        # 数据检查
        log.warning(
            '2、下发http的get黑名单，参数为：hello、juson；post黑名单：123、456；uri黑名单：mzh、hkl；MIME白名单：css、avi，等待nginx的24个进程起来;预期cat /etc/jsac/http.json文件应该包含：c_get_args和get黑名单参数：123')
        fun.send(rbmExc,
                tool.interface().app_safe_policy(prototype='httpcheck', uri_data=f"{self.check1_uri1};{self.check1_uri2}",
                                    mime_action=0,
                                    mime_data=f"{self.MIME1_uri1};{self.MIME1_uri2}",
                                    content_get_data=f"{self.get1_data1};{self.get1_data2}",
                                    content_post_data=f"{self.post1_data1};{self.post1_data2}"), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'FrontDut', self.case1_step2[key][1], '配置', 100)
            assert self.case1_step2[key][1] in re

        # 1、发送get请求，不包含黑名单内容的普通请求
        log.warning('3、控制台发送get请求，不包含请求内容；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_get(http_url)
        log.warning('1、get普通请求的请求内容为：{}'.format(content))
        assert content == http_content

        # 2、发送post请求，不包含黑名单内容的普通请求
        log.warning('4、控制台发送post请求，不包含请求内容；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_post(http_url)
        log.warning('2、post普通请求的请求内容为：{}'.format(content))
        assert content == http_content

        # 3、发送get请求，请求内容包含第一个get黑名单
        log.warning('控制台发送get请求，请求内容包含get黑名单hello；请求失败，状态码返回为403')
        status_code1 = http_check.http_get(http_url, self.case1_get_data1)
        log.warning('3、get请求内容包含第一个get黑名单返回的状态码为：{}'.format(status_code1))
        assert status_code1 == 403

        # 4、发送get请求，请求内容包含第二个get黑名单
        log.warning('6、控制台发送get请求，请求内容包含get黑名单juson；请求失败，状态码返回为403')
        status_code2 = http_check.http_get(http_url, self.case1_get_data2)
        log.warning('4、get请求内容包含第二个get黑名单返回的状态码为：{}'.format(status_code2))
        assert status_code2 == 403

        # 发送get请求，请求内容包含第一个uri黑名单
        log.warning('7、控制台发送get请求，请求内容包含uri黑名单mzh；请求失败，状态码返回为403')
        status_code3 = http_check.http_get(self.case1_uri1, self.data)
        log.warning('get请求内容包含第一个uri黑名单返回的状态码为：{}'.format(status_code3))
        assert status_code3 == 403

        # 6、发送get请求，请求内容包含第二个uri黑名单
        log.warning('8、控制台发送get请求，请求内容包含uri黑名单hkl；请求失败，状态码返回为403')
        status_code4 = http_check.http_get(self.case1_uri2, self.data)
        log.warning('6、get请求内容包含第二个uri黑名单返回的状态码为：{}'.format(status_code4))
        assert status_code4 == 403

        # 7、发送get请求，请求内容包含第一个post黑名单
        log.warning('9、控制台发送get请求，请求内容包含post黑名单123；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_get(http_url, self.case1_post_data1)
        log.warning('7、get请求内容包含第一个post黑名单的请求内容为：{}'.format(content))
        assert content == http_content

        # 8、发送get请求，请求内容包含第二个post黑名单
        log.warning('10、控制台发送get请求，请求内容包含post黑名单456；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_get(http_url, self.case1_post_data2)
        log.warning('8、get请求内容包含第二个post黑名单的请求内容为：{}'.format(content))
        assert content == http_content

        # 9、发送post请求，请求内容包含第一个post黑名单
        log.warning('11、控制台发送post请求，请求内容包含post黑名单123；请求失败，状态码返回为403')
        status_code5 = http_check.http_post(http_url, self.case1_post_data1)
        log.warning('9、post请求内容包含第一个post黑名单返回的状态码为：{}'.format(status_code5))
        assert status_code5 == 403

        # 10、发送post请求，请求内容包含第二个post黑名单
        log.warning('12、控制台发送post请求，请求内容包含post黑名单456；请求失败，状态码返回为403')
        status_code6 = http_check.http_post(http_url, self.case1_post_data2)
        log.warning('10、post请求内容包含第二个post黑名单返回的状态码为：{}'.format(status_code6))
        assert status_code6 == 403

        # 11、发送post请求，请求内容包含第一个uri黑名单
        log.warning('13、控制台发送post请求，请求内容包含uri黑名单mzh；请求失败，状态码返回为403')
        status_code7 = http_check.http_post(self.case1_uri1, self.data)
        log.warning('11、post请求内容包含第一个uri黑名单返回的状态码为：{}'.format(status_code7))
        assert status_code7 == 403

        # 12、发送post请求，请求内容包含第二个uri黑名单
        log.warning('14、控制台发送post请求，请求内容包含uri黑名单hkl；请求失败，状态码返回为403')
        status_code8 = http_check.http_post(self.case1_uri2, self.data)
        log.warning('12、post请求内容包含第二个uri黑名单返回的状态码为：{}'.format(status_code8))
        assert status_code8 == 403

        # 13、发送post请求，请求内容包含第一个get黑名单
        log.warning('15、控制台发送post请求，请求内容包含get黑名单hello；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_post(http_url, self.case1_get_data1)
        log.warning('13、post请求内容包含第一个get黑名单的请求内容为：{}'.format(content))
        assert content == http_content

        # 14、发送post请求，请求内容包含第二个get黑名单
        log.warning('16、控制台发送post请求，请求内容包含get黑名单juson；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_post(http_url, self.case1_get_data2)
        log.warning('14、post请求内容包含第二个get黑名单的请求内容为：{}'.format(content))
        assert content == http_content

        # 15、发送get请求，请求内容包含第一个MIME白名单
        log.warning('17、控制台发送get请求，请求内容包含MIME白名单css；请求成功，状态码返回为200')
        status_code9 = http_check.http_get(self.case1_MIME1, self.data, flag=1)
        log.warning('15、get请求内容包含第一个MIME白名单返回的状态码为：{}'.format(status_code9))
        assert status_code9 == 200

        # 16、发送get请求，请求内容包含第二个MIME白名单
        log.warning('18、控制台发送get请求，请求内容包含MIME白名单avi；请求成功，状态码返回为200')
        status_code10 = http_check.http_get(self.case1_MIME2, self.data, flag=1)
        log.warning('16、get请求内容包含第二个MIME白名单返回的状态码为：{}'.format(status_code10))
        assert status_code10 == 200

        # 17、发送get请求，请求内容包含MIME类型不在白名单
        log.warning('19、控制台发送get请求，请求内容包含MIME类型但不在其白名单：pdf；请求失败，状态码返回为403')
        status_code11 = http_check.http_get(self.base_uri, self.data, flag=1)
        log.warning('17、get请求内容包含MIME类型不在白名单返回的状态码为：{}'.format(status_code11))
        assert status_code11 == 403

        # 18、发送get请求，请求内容包含MIME白名单和get黑名单
        log.warning('20、控制台发送get请求，请求内容包含MIME白名单：css和get黑名单：juson；请求失败，状态码返回为403')
        status_code12 = http_check.http_get(self.case1_MIME1, self.case1_get_data2, flag=1)
        log.warning('18、get请求内容包含MIME白名单和get黑名单返回的状态码为：{}'.format(status_code12))
        assert status_code12 == 403

        # 19、发送get请求，请求内容包含MIME白名单和post黑名单
        log.warning('21、控制台发送get请求，请求内容包含MIME白名单：avi和post黑名单：123；请求成功，状态码返回为200')
        status_code13 = http_check.http_get(self.case1_MIME2, self.case1_post_data1, flag=1)
        log.warning('19、get请求内容包含MIME白名单和post黑名单返回的状态码为：{}'.format(status_code13))
        assert status_code13 == 200

        # 移除策略，还原环境
        log.warning('22、移除代理策略，清空环境，等待nginx的24个进程起来;netstat -anp |grep tcp应该查看不到监听ip和端口')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100, flag='不存在')
            log.warning(re)
            assert self.case1_step1[key][1] not in re

        # 检查网页访问策略是否清空
        log.warning('23、移除网页访问策略，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该不包含：http协议')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1
        for key in self.delcheck:
            re = fun.wait_data(self.delcheck[key][0], 'FrontDut', self.delcheck[key][1], '配置', 100, flag='不存在')
            assert self.delcheck[key][1] not in re

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于URI黑名单、get请求方法、post请求方法、MIME多种类型设置阻断的网页访问策略')
    def test_iso_http_check_get_post_uri_MIME_a2(self):
        # 下发配置
        log.warning('1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来;预期netstat -anp |grep tcp应该可以查看到监听ip和端口')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step11[key][1] in re

        # 数据检查
        log.warning(
            '2、下发http的get黑名单，参数为：hello、juson；post黑名单：123、456；uri黑名单：mzh、hkl；MIME黑名单：css、avi，等待nginx的24个进程起来;预期cat /etc/jsac/http.json文件应该包含：c_get_args和get黑名单参数：123')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', uri_data=f"{self.check1_uri1};{self.check1_uri2}",
                                            mime_action=1, mime_data=f"{self.MIME1_uri1};{self.MIME1_uri2}",
                                            content_get_data=f"{self.get1_data1};{self.get1_data2}",
                                            content_post_data=f"{self.post1_data1};{self.post1_data2}"), FrontDomain,
                 base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1
        for key in self.case2_step2:
            re = fun.wait_data(self.case2_step2[key][0], 'FrontDut', self.case2_step2[key][1], '配置', 100)
            assert self.case2_step2[key][1] in re

        # 1、发送get请求，不包含黑名单内容的普通请求
        log.warning('3、控制台发送get请求，不包含请求内容；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_get(http_url)
        log.warning('1、get普通请求的请求内容为：{}'.format(content))
        assert content == http_content

        # 2、发送post请求，不包含黑名单内容的普通请求
        log.warning('4、控制台发送post请求，不包含请求内容；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_post(http_url)
        log.warning('2、post普通请求的请求内容为：{}'.format(content))
        assert content == http_content

        # 3、发送get请求，请求内容包含第一个get黑名单
        log.warning('5、控制台发送get请求，请求内容包含get黑名单hello；请求失败，状态码返回为403')
        status_code = http_check.http_get(http_url, self.case1_get_data1)
        log.warning('3、get请求内容包含第一个get黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 4、发送get请求，请求内容包含第二个get黑名单
        log.warning('6、控制台发送get请求，请求内容包含get黑名单juson；请求失败，状态码返回为403')
        status_code = http_check.http_get(http_url, self.case1_get_data2)
        log.warning('4、get请求内容包含第二个get黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 5、发送get请求，请求内容包含第一个uri黑名单
        log.warning('7、控制台发送get请求，请求内容包含uri黑名单mzh；请求失败，状态码返回为403')
        status_code = http_check.http_get(self.case1_uri1, self.data)
        log.warning('5、get请求内容包含第一个uri黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 6、发送get请求，请求内容包含第二个uri黑名单
        log.warning('8、控制台发送get请求，请求内容包含uri黑名单hkl；请求失败，状态码返回为403')
        status_code = http_check.http_get(self.case1_uri2, self.data)
        log.warning('6、get请求内容包含第二个uri黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 7、发送get请求，请求内容包含第一个post黑名单
        log.warning('9、控制台发送get请求，请求内容包含post黑名单123；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_get(http_url, self.case1_post_data1)
        log.warning('7、get请求内容包含第一个post黑名单的请求内容为：{}'.format(content))
        assert content == http_content

        # 8、发送get请求，请求内容包含第二个post黑名单
        log.warning('10、控制台发送get请求，请求内容包含post黑名单456；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_get(http_url, self.case1_post_data2)
        log.warning('8、get请求内容包含第二个post黑名单的请求内容为：{}'.format(content))
        assert content == http_content

        # 9、发送post请求，请求内容包含第一个post黑名单
        log.warning('11、控制台发送post请求，请求内容包含post黑名单123；请求失败，状态码返回为403')
        status_code = http_check.http_post(http_url, self.case1_post_data1)
        log.warning('9、post请求内容包含第一个post黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 10、发送post请求，请求内容包含第二个post黑名单
        log.warning('12、控制台发送post请求，请求内容包含post黑名单456；请求失败，状态码返回为403')
        status_code = http_check.http_post(http_url, self.case1_post_data2)
        log.warning('10、post请求内容包含第二个post黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 11、发送post请求，请求内容包含第一个uri黑名单
        log.warning('13、控制台发送post请求，请求内容包含uri黑名单mzh；请求失败，状态码返回为403')
        status_code = http_check.http_post(self.case1_uri1, self.data)
        log.warning('11、post请求内容包含第一个uri黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 12、发送post请求，请求内容包含第二个uri黑名单
        log.warning('14、控制台发送post请求，请求内容包含uri黑名单hkl；请求失败，状态码返回为403')
        status_code = http_check.http_post(self.case1_uri2, self.data)
        log.warning('12、post请求内容包含第二个uri黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 13、发送post请求，请求内容包含第一个get黑名单
        log.warning('15、控制台发送post请求，请求内容包含get黑名单hello；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_post(http_url, self.case1_get_data1)
        log.warning('13、post请求内容包含第一个get黑名单的请求内容为：{}'.format(content))
        assert content == http_content

        # 14、发送post请求，请求内容包含第二个get黑名单
        log.warning('16、控制台发送post请求，请求内容包含get黑名单juson；请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_post(http_url, self.case1_get_data2)
        log.warning('14、post请求内容包含第二个get黑名单的请求内容为：{}'.format(content))
        assert content == http_content

        # 15、发送get请求，请求内容包含第一个MIME黑名单
        log.warning('17、控制台发送get请求，请求内容包含MIME黑名单css；请求失败，状态码返回为403')
        status_code = http_check.http_get(self.case1_MIME1, self.data, flag=1)
        log.warning('15、get请求内容包含第一个MIME黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 16、发送get请求，请求内容包含第二个MIME黑名单
        log.warning('18、控制台发送get请求，请求内容包含MIME黑名单avi；请求失败，状态码返回为403')
        status_code = http_check.http_get(self.case1_MIME2, self.data, flag=1)
        log.warning('16、get请求内容包含第二个MIME黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 17、发送get请求，请求内容包含MIME类型不在黑名单
        log.warning('19、控制台发送get请求，请求内容包含MIME类型但不在黑白名单：pdf；请求成功，状态码返回为200')
        status_code = http_check.http_get(self.base_uri, self.data, flag=1)
        log.warning('17、get请求内容包含MIME类型不在白名单返回的状态码为：{}'.format(status_code))
        assert status_code == 200

        # 18、发送get请求，请求内容包含MIME黑名单和post黑名单
        log.warning('20、控制台发送get请求，请求内容包含MIME黑名单：avi和post黑名单：123；请求失败，状态码返回为403')
        status_code = http_check.http_get(self.case1_MIME2, self.case1_post_data1, flag=1)
        log.warning('18、get请求内容包含MIME黑名单和post黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 18、发送get请求，请求内容包含MIME类型不为黑名单和get黑名单
        log.warning('21、控制台发送get请求，请求内容包含MIME类型但不在黑名单：pdf和get黑名单：hello；请求失败，状态码返回为403')
        status_code = http_check.http_get(self.base_uri, self.case1_get_data1, flag=1)
        log.warning('18、get请求内容包含MIME类型不为黑名单和get黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 移除策略，还原环境
        log.warning('22、移除代理策略，清空环境，等待nginx的24个进程起来;netstat -anp |grep tcp应该查看不到监听ip和端口；')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100, flag='不存在')
            log.warning(re)
            assert self.case1_step1[key][1] not in re

        # 检查网页访问策略是否清空
        log.warning('23、移除网页访问策略，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该不包含：http协议')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1
        for key in self.delcheck:
            re = fun.wait_data(self.delcheck[key][0], 'FrontDut', self.delcheck[key][1], '配置', 100, flag='不存在')
            assert self.delcheck[key][1] not in re

    def teardown_class(self):
        # 回收环境
        clr_env.iso_setup_class(dut='FrontDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')

