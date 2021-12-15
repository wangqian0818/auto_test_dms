# encoding='utf-8'
try:
    import os, sys, pytest, allure, time, re, time, logging
except Exception as err:
    print('导入CPython内置函数库失败!错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

log = logging.getLogger(__name__)
base_path = os.path.dirname(os.path.abspath(__file__))  # 获取当前项目文件夹
base_path = base_path.replace('\\', '/')
sys.path.insert(0, base_path)  # 将当前目录添加到系统环境变量,方便下面导入版本配置等文件
log.warning(base_path)
try:
    from Case_rbm.http_check_post_param import index
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


class Test_http_check_post():

    def setup_method(self):
        clr_env.data_check_setup_met()

    def teardown_method(self):
        clr_env.data_check_teardown_met('http', base_path)

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.clr_env = clr_env
        self.method = index.method
        self.case1_parameter = index.case1_parameter
        self.check1_url1 = index.check1_url1
        self.case2_parameter = index.case2_parameter
        self.check2_url1 = index.check2_url1
        self.check2_url2 = index.check2_url2
        self.check_url = index.check_url

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于post方法的网页访问策略的过滤')
    def test_http_check_post_a1(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy()

        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', method=self.method,
                                                        parameter=self.case1_parameter), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查网页应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) in re

        # 发送post请求，不包含黑名单内容的普通请求
        status_code = http_check.http_post(url)
        log.warning('post普通请求的请求【{}】内容为：{}'.format(url,content))
        assert status_code == http_content

        # 发送post请求，请求内容不包含黑名单内容
        status = http_check.http_post(self.check_url, flag=1)
        log.warning('post请求内容不包含黑名单的请求【{}】应返回的状态码为：{}'.format(self.check_url, status))
        assert status == 200

        # 发送post请求，请求内容包含黑名单
        status_code = http_check.http_post(self.check1_url1, flag=1)
        log.warning('post请求内容包含黑名单【{}】返回的状态码为：{}'.format(self.check1_url1, status_code))
        assert status_code == 405

        # 检查网页访问策略是否清空
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查网页应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid, flag=False)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) not in re

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(flag=False)

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于post方法的多个网页访问策略的过滤')
    def test_http_check_post_a2(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy()

        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', method=self.method,
                                                        parameter=self.case2_parameter), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查网页应用安全策略是否下发成功')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) in re

        # 发送post请求，不包含黑名单内容的普通请求
        status_code = http_check.http_post(url)
        log.warning('多个黑名单时post普通请求的请求内容为：{}'.format(status_code))
        assert status_code == http_content

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

        log.warning('检查网页应用安全策略是否移除成功')
        re = fun.wait_data(type=3, dut='gw', context=http_ruleid, flag=False)
        log.warning('预期包含内容：{}'.format(http_ruleid))
        log.warning('查询http.json命令返回值：\n{}'.format(re))
        assert str(http_ruleid) not in re

    # def teardown_class(self):
    #     # 回收环境
    #     clr_env.clear_env()
    #
    #     fun.rbm_close()
    #     fun.ssh_close('gw')
