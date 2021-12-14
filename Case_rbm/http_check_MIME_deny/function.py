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
    from Case_rbm.http_check_MIME_deny import index
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
http_content = baseinfo.http_content

http_ruleid = baseinfo.http_ruleid


class Test_http_check_MIME_deny():

    def setup_method(self):
        clr_env.data_check_setup_met()

    def teardown_method(self):
        clr_env.data_check_teardown_met('http', base_path)

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.clr_env = clr_env
        self.data = index.data
        self.action = index.action
        self.MIME_all = index.MIME_all
        self.case1_uri = index.case1_uri
        self.case2_uri1 = index.case2_uri1
        self.case2_uri2 = index.case2_uri2
        self.case2_uri3 = index.case2_uri3
        self.case2_uri4 = index.case2_uri4
        self.case2_uri5 = index.case2_uri5
        self.base_uri = index.base_uri

        self.proxy_port = index.proxy_port
        self.check1_uri = index.check1_uri
        self.check2_uri = index.check2_uri

        clr_env.clear_env()

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于一种MIME类型设置阻断的网页访问策略')
    def test_http_check_MIME_deny_a1(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy()

        fun.send(rbmExc,
                 tool.interface().app_safe_policy(prototype='httpcheck', mime_data=self.check1_uri,
                                                check_action=self.action), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查网页应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) in re
        assert self.check1_uri in re

        # # 发送get请求，不指定内容的普通请求
        # content = http_check.http_get(url)
        # log.warning('get普通请求的请求内容为：{}'.format(content))
        # assert content == http_content
        #
        # # 发送get请求，请求内容不包含MIME黑名单
        # status_code = http_check.http_get(self.base_uri, self.data, flag=1)
        # log.warning('get请求内容不包含MIME黑名单返回的状态码为：{}'.format(status_code))
        # assert status_code == 200
        #
        # # 发送get请求，请求内容包含MIME黑名单
        # status_code = http_check.http_get(self.case1_uri, self.data, flag=1)
        # log.warning('get请求内容包含MIME黑名单返回的状态码为：{}'.format(status_code))
        # assert status_code == 405

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
        assert self.check1_uri not in re

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于多种MIME类型设置阻断的网页访问策略')
    def test_http_check_MIME_deny_a2(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy()

        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', mime_data=self.check2_uri,
                                                        check_action=self.action), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查网页应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) in re
        for mime in self.check2_uri:
            assert mime in re

        # 发送get请求，不指定内容的普通请求
        content = http_check.http_get(url)
        log.warning('get普通请求的请求内容为：{}'.format(content))
        assert content == http_content

        # 发送get请求，请求内容不包含MIME黑名单
        status_code = http_check.http_get(self.base_uri, self.data, flag=1)
        log.warning('get请求内容不包含MIME黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 200

        # 发送get请求，请求内容包含MIME第一个黑名单
        status_code1 = http_check.http_get(self.case2_uri1, self.data, flag=1)
        log.warning('get请求内容包含MIM第一个黑名单{}返回的状态码为：{}'.format(self.case2_uri1, status_code1))
        assert status_code1 == 405

        # 发送get请求，请求内容包含MIME第二个黑名单
        status_code2 = http_check.http_get(self.case2_uri2, self.data, flag=1)
        log.warning('get请求内容包含MIM第二个黑名单{}返回的状态码为：{}'.format(self.case2_uri2, status_code2))
        assert status_code2 == 405

        # 发送get请求，请求内容包含MIME第三个黑名单
        status_code3 = http_check.http_get(self.case2_uri3, self.data, flag=1)
        log.warning('get请求内容包含MIM第三个黑名单{}返回的状态码为：{}'.format(self.case2_uri3, status_code3))
        assert status_code3 == 405

        # 发送get请求，请求内容包含MIME第四个黑名单
        status_code4 = http_check.http_get(self.case2_uri4, self.data, flag=1)
        log.warning('get请求内容包含MIM第四个黑名单{}返回的状态码为：{}'.format(self.case2_uri4, status_code4))
        assert status_code4 == 405

        # 发送get请求，请求内容包含MIME第五个黑名单
        status_code5 = http_check.http_get(self.case2_uri5, self.data, flag=1)
        log.warning('get请求内容包含MIM第五个黑名单{}返回的状态码为：{}'.format(self.case2_uri5, status_code5))
        assert status_code5 == 405

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
        for mime in self.check2_uri:
            assert mime not in re

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于所有MIME类型设置阻断的网页访问策略')
    def test_http_check_MIME_deny_a3(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy()

        # 下发网页网页访问策略
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', check_action=self.action,
                                                        mime_data=self.MIME_all.split(';')), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查网页应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) in re
        for mime in self.MIME_all.split(';'):
            assert mime in re
        #
        # # 发送get请求，不指定内容的普通请求
        # content = http_check.http_get(url)
        # log.warning('get普通请求的请求内容为：{}'.format(content))
        # assert content == http_content
        #
        # # 发送get请求，请求内容包含MIME黑名单
        # status_code = http_check.http_get(self.base_uri, self.data, flag=1)
        # log.warning('get请求内容包含MIME黑名单返回的状态码为：{}'.format(status_code))
        # assert status_code == 405
        #
        # # 发送get请求，请求内容包含MIME第一个黑名单
        # status_code1 = http_check.http_get(self.case2_uri1, self.data, flag=1)
        # log.warning('get请求内容包含MIM第一个黑名单{}返回的状态码为：{}'.format(self.case2_uri1, status_code1))
        # assert status_code1 == 405
        #
        # # 发送get请求，请求内容包含MIME第二个黑名单
        # status_code2 = http_check.http_get(self.case2_uri2, self.data, flag=1)
        # log.warning('get请求内容包含MIM第二个黑名单{}返回的状态码为：{}'.format(self.case2_uri2, status_code2))
        # assert status_code2 == 405
        #
        # # 发送get请求，请求内容包含MIME第三个黑名单
        # status_code3 = http_check.http_get(self.case2_uri3, self.data, flag=1)
        # log.warning('get请求内容包含MIM第三个黑名单{}返回的状态码为：{}'.format(self.case2_uri3, status_code3))
        # assert status_code3 == 405
        #
        # # 发送get请求，请求内容包含MIME第四个黑名单
        # status_code4 = http_check.http_get(self.case2_uri4, self.data, flag=1)
        # log.warning('get请求内容包含MIM第四个黑名单{}返回的状态码为：{}'.format(self.case2_uri4, status_code4))
        # assert status_code4 == 405
        #
        # # 发送get请求，请求内容包含MIME第五个黑名单
        # status_code5 = http_check.http_get(self.case2_uri5, self.data, flag=1)
        # log.warning('get请求内容包含MIM第五个黑名单{}返回的状态码为：{}'.format(self.case2_uri5, status_code5))
        # assert status_code5 == 405

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
        for mime in self.MIME_all.split(';'):
            assert mime not in re

    # def teardown_class(self):
    #     # 回收环境
    #     clr_env.clear_env()
    #
    #     fun.rbm_close()
    #     fun.ssh_close('gw')
