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
    from Case_rbm.http_check_get_post_uri_MIME import index
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

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
url = baseinfo.http_proxy_url
http_ruleid = baseinfo.http_ruleid
http_content = baseinfo.http_content


class Test_http_check_get_post_uri_MIME():

    # def setup_method(self):
    #     clr_env.data_check_setup_met()
    #
    # def teardown_method(self):
    #     clr_env.data_check_teardown_met('http', base_path)

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.clr_env = clr_env
        self.ruleid = index.ruleid
        self.check1_method = index.check1_method
        self.check1_uri = index.check1_uri
        self.check1_parameter = index.check1_parameter
        self.check1_MIME = index.check1_MIME
        self.case1_url1 = index.case1_url1
        self.case1_url2 = index.case1_url2
        self.case1_url3 = index.case1_url3
        self.case1_url4 = index.case1_url4
        self.case1_url5 = index.case1_url5
        self.case1_url6 = index.case1_url6
        self.case1_url7 = index.case1_url7
        self.case1_url8 = index.case1_url8

        clr_env.clear_env()

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于URI黑名单、get请求方法、post请求方法、MIME多种类型设置放行的网页访问策略')
    def test_http_check_get_post_uri_MIME_a1(self):
        # 下发代理配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1

        # 检查代理策略是否下发成功
        fun.check_proxy_policy()

        # 下发数据结构检查策略
        # 黑名单和白名单策略需要分开发
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', method=self.check1_method,
                                                        uri_data=self.check1_uri, parameter=self.check1_parameter),
                 rbmDomain, base_path)
        fun.send(rbmExc,
                 tool.interface().app_safe_policy(prototype='httpcheck', method=self.check1_method, check_action='allow',
                                                mime_data=self.check1_MIME, ruleid=self.ruleid), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查网页应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) in re
        assert str(self.ruleid) in re

        # 1、发送get请求，不包含黑名单内容的普通请求
        status_code = http_check.http_get(url, flag=1)
        log.warning('1、get普通请求的请求内容为：{}'.format(status_code))
        assert status_code == 200

        # 2、发送post请求，不包含黑名单内容的普通请求
        status_code = http_check.http_post(url)
        log.warning('2、post普通请求的请求内容为：{}'.format(status_code))
        assert status_code == http_content

        # 3、发送get请求，请求内容包含第一个黑名单
        status_code1 = http_check.http_get(self.case1_url1, flag=1)
        log.warning('3、get请求内容包含第一个黑名单返回的状态码为：{}'.format(status_code1))
        assert status_code1 == 405

        # 4、发送get请求，请求内容包含第二个黑名单
        status_code2 = http_check.http_get(self.case1_url2, flag=1)
        log.warning('4、get请求内容包含第二个黑名单返回的状态码为：{}'.format(status_code2))
        assert status_code2 == 405

        # 5、发送get请求，请求内容包含第三个黑名单
        status_code3 = http_check.http_get(self.case1_url3, flag=1)
        log.warning('5、get请求内容包含第三个黑名单返回的状态码为：{}'.format(status_code3))
        assert status_code3 == 405

        # 6、发送get请求，请求内容包含第四个黑名单
        status_code4 = http_check.http_get(self.case1_url4, flag=1)
        log.warning('6、get请求内容包含第四个黑名单返回的状态码为：{}'.format(status_code4))
        assert status_code4 == 405

        # 7、发送get请求，请求内容包含第一个uri黑名单_第一个MIME白名单
        status_code = http_check.http_get(self.case1_url5, flag=1)
        log.warning('7、get请求内容包含第一个uri黑名单_第一个MIME白名单的请求内容为：{}'.format(status_code))
        assert content != 405

        # 8、发送get请求，请求内容包含第一个uri黑名单_第二个MIME白名单
        status_code = http_check.http_get(self.case1_url6, flag=1)
        log.warning('8、get请求内容包含第一个uri黑名单_第二个MIME白名单的请求内容为：{}'.format(status_code))
        assert content != 405

        # 9、发送get请求，请求内容包含第二个uri黑名单_第一个MIME白名单
        status_code5 = http_check.http_get(self.case1_url7, flag=1)
        log.warning('9、get请求内容包含第二个uri黑名单_第一个MIME白名单返回的状态码为：{}'.format(status_code5))
        # assert status_code5 != 405

        # 10、发送get请求，请求内容包含第二个uri黑名单_第二个MIME白名单
        status_code6 = http_check.http_get(self.case1_url8, flag=1)
        log.warning('10、get请求内容包含第二个uri黑名单_第二个MIME白名单返回的状态码为：{}'.format(status_code6))
        # assert status_code6 != 405

        # 11、发送post请求，请求内容包含第一个黑名单
        status_code7 = http_check.http_post(self.case1_url1, flag=1)
        log.warning('11、post请求内容包含第一个黑名单返回的状态码为：{}'.format(status_code7))
        assert status_code7 == 405

        # 12、发送post请求，请求内容包含第二个黑名单
        status_code8 = http_check.http_post(self.case1_url2, flag=1)
        log.warning('12、post请求内容包含第二个黑名单返回的状态码为：{}'.format(status_code8))
        assert status_code8 == 405

        # 13、发送post请求，请求内容包含第三个黑名单
        status_code = http_check.http_post(self.case1_url3, flag=1)
        log.warning('13、post请求内容包含第三个黑名单的请求内容为：{}'.format(status_code))
        assert status_code == 405

        # 14、发送post请求，请求内容包含第四个黑名单
        status_code = http_check.http_post(self.case1_url4, flag=1)
        log.warning('14、post请求内容包含第四个黑名单的请求内容为：{}'.format(status_code))
        assert status_code == 405

        # 15、发送post请求，请求内容包含第一个uri黑名单_第一个MIME白名单
        status_code9 = http_check.http_post(self.case1_url5, flag=1)
        log.warning('15、post请求内容包含第一个uri黑名单_第一个MIME白名单返回的状态码为：{}'.format(status_code9))
        assert status_code9 != 405

        # 16、发送post请求，请求内容包含第一个uri黑名单_第二个MIME白名单
        status_code10 = http_check.http_post(self.case1_url6, flag=1)
        log.warning('16、post请求内容包含第一个uri黑名单_第二个MIME白名单返回的状态码为：{}'.format(status_code10))
        assert status_code10 != 405

        # 17、发送post请求，请求内容包含第二个uri黑名单_第一个MIME白名单
        status_code11 = http_check.http_post(self.case1_url7, flag=1)
        log.warning('17、post请求内容包含第二个uri黑名单_第一个MIME白名单返回的状态码为：{}'.format(status_code11))
        assert status_code11 != 405

        # 18、发送post请求，请求内容包含第二个uri黑名单_第二个MIME白名单
        status_code12 = http_check.http_post(self.case1_url8, flag=1)
        log.warning('18、post请求内容包含第二个uri黑名单_第二个MIME白名单返回的状态码为：{}'.format(status_code12))
        assert status_code12 != 405

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(flag=False)

        # 检查网页访问策略是否清空
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查网页安全浏览策略是否清空')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) not in re
        assert str(self.ruleid) not in re

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于URI黑名单、get请求方法、post请求方法、MIME多种类型设置阻断的网页访问策略')
    def test_http_check_get_post_uri_MIME_a2(self):
        # 下发代理配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1

        # 检查代理策略是否下发成功
        fun.check_proxy_policy()

        # 下发数据结构检查策略
        # 黑名单和白名单策略需要分开发
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', method=self.check1_method,
                                                        uri_data=self.check1_uri, parameter=self.check1_parameter,
                                                        mime_data=self.check1_MIME), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查网页应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) in re

        # 1、发送get请求，不包含黑名单内容的普通请求
        status_code = http_check.http_get(url, flag=1)
        log.warning('1、get普通请求的请求内容为：{}'.format(status_code))
        assert status_code == 200

        # 2、发送post请求，不包含黑名单内容的普通请求
        status_code = http_check.http_post(url)
        log.warning('2、post普通请求的请求内容为：{}'.format(status_code))
        assert status_code == http_content

        # 3、发送get请求，请求内容包含第一个黑名单
        status_code1 = http_check.http_get(self.case1_url1, flag=1)
        log.warning('3、get请求内容包含第一个黑名单返回的状态码为：{}'.format(status_code1))
        assert status_code1 == 405

        # 4、发送get请求，请求内容包含第二个黑名单
        status_code2 = http_check.http_get(self.case1_url2, flag=1)
        log.warning('4、get请求内容包含第二个黑名单返回的状态码为：{}'.format(status_code2))
        assert status_code2 == 405

        # 5、发送get请求，请求内容包含第三个黑名单
        status_code3 = http_check.http_get(self.case1_url3, flag=1)
        log.warning('5、get请求内容包含第三个黑名单返回的状态码为：{}'.format(status_code3))
        assert status_code3 == 405

        # 6、发送get请求，请求内容包含第四个黑名单
        status_code4 = http_check.http_get(self.case1_url4, flag=1)
        log.warning('6、get请求内容包含第四个黑名单返回的状态码为：{}'.format(status_code4))
        assert status_code4 == 405

        # 7、发送get请求，请求内容包含第一个uri黑名单_第一个MIME黑名单
        status_code = http_check.http_get(self.case1_url5, flag=1)
        log.warning('7、get请求内容包含第一个uri黑名单_第一个MIME白名单的请求内容为：{}'.format(status_code))
        assert status_code == 405

        # 8、发送get请求，请求内容包含第一个uri黑名单_第二个MIME黑名单
        status_code = http_check.http_get(self.case1_url6, flag=1)
        log.warning('8、get请求内容包含第一个uri黑名单_第二个MIME白名单的请求内容为：{}'.format(status_code))
        assert status_code == 405

        # 9、发送get请求，请求内容包含第二个uri黑名单_第一个MIME黑名单
        status_code5 = http_check.http_get(self.case1_url7, flag=1)
        log.warning('9、get请求内容包含第二个uri黑名单_第一个MIME白名单返回的状态码为：{}'.format(status_code5))
        assert status_code5 == 405

        # 10、发送get请求，请求内容包含第二个uri黑名单_第二个MIME黑名单
        status_code6 = http_check.http_get(self.case1_url8, flag=1)
        log.warning('10、get请求内容包含第二个uri黑名单_第二个MIME白名单返回的状态码为：{}'.format(status_code6))
        assert status_code6 == 405

        # 11、发送post请求，请求内容包含第一个黑名单
        status_code7 = http_check.http_post(self.case1_url1, flag=1)
        log.warning('11、post请求内容包含第一个黑名单返回的状态码为：{}'.format(status_code7))
        assert status_code7 == 405

        # 12、发送post请求，请求内容包含第二个黑名单
        status_code8 = http_check.http_post(self.case1_url2, flag=1)
        log.warning('12、post请求内容包含第二个黑名单返回的状态码为：{}'.format(status_code8))
        assert status_code8 == 405

        # 13、发送post请求，请求内容包含第三个黑名单
        status_code = http_check.http_post(self.case1_url3, flag=1)
        log.warning('13、post请求内容包含第三个黑名单的请求内容为：{}'.format(status_code))
        assert status_code == 405

        # 14、发送post请求，请求内容包含第四个黑名单
        status_code = http_check.http_post(self.case1_url4, flag=1)
        log.warning('14、post请求内容包含第四个黑名单的请求内容为：{}'.format(status_code))
        assert status_code == 405

        # 15、发送post请求，请求内容包含第一个uri黑名单_第一个MIME白名单
        status_code9 = http_check.http_post(self.case1_url5, flag=1)
        log.warning('15、post请求内容包含第一个uri黑名单_第一个MIME黑名单返回的状态码为：{}'.format(status_code9))
        assert status_code9 == 405

        # 16、发送post请求，请求内容包含第一个uri黑名单_第二个MIME白名单
        status_code10 = http_check.http_post(self.case1_url6, flag=1)
        log.warning('16、post请求内容包含第一个uri黑名单_第二个MIME黑名单返回的状态码为：{}'.format(status_code10))
        assert status_code10 == 405

        # 17、发送post请求，请求内容包含第二个uri黑名单_第一个MIME白名单
        status_code11 = http_check.http_post(self.case1_url7, flag=1)
        log.warning('17、post请求内容包含第二个uri黑名单_第一个MIME黑名单返回的状态码为：{}'.format(status_code11))
        assert status_code11 == 405

        # 18、发送post请求，请求内容包含第二个uri黑名单_第二个MIME白名单
        status_code12 = http_check.http_post(self.case1_url8, flag=1)
        log.warning('18、post请求内容包含第二个uri黑名单_第二个MIME黑名单返回的状态码为：{}'.format(status_code12))
        assert status_code12 == 405

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(flag=False)

        # 检查网页访问策略是否清空
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查网页安全浏览策略是否清空')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) not in re

    # def teardown_class(self):
    #     # 回收环境
    #     clr_env.clear_env()
    #
    #     fun.rbm_close()
    #     fun.ssh_close('gw')
