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
    from Case_rbm.ftp_check_user import index
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
from data_check import con_ftp

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
proxy_ip = baseinfo.gwClientIp
smtp_ip = baseinfo.smtp_ip
ftp_ruleid = baseinfo.ftp_ruleid


class Test_ftp_check_user():

    def setup_method(self):
        clr_env.data_check_setup_met()

    def teardown_method(self):
        clr_env.data_check_teardown_met('ftp', base_path)

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.clr_env = clr_env
        self.action = index.action
        self.host = index.host
        self.port = index.port
        self.username = index.username
        self.password = index.password
        self.case1_deny_user = index.case1_deny_user
        self.data2_check = index.data2_check
        self.case2_deny_user = index.case2_deny_user
        self.case2_allow_user = index.case2_allow_user

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于用户白名单过滤的FTP传输策略')
    def test_ftp_check_user_a1(self):

        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='gw', type='ftp')

        log.warning('self.host, self.port, self.username, self.password:', self.host, self.port, self.username,
                    self.password)
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='ftpcheck', user_data=self.username,
                                                        check_action=self.action), rbmDomain,
                 base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查ftp应用安全策略是否下发成功')
        re = fun.wait_data(type=4, dut='gw', context=ftp_ruleid)
        log.warning('预期包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) in re

        # 登录ftp服务器，用户为白名单用户
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('ftp白名单{}欢迎语是：{}'.format(self.username, fp.getwelcome()))
        assert '220' in fp.getwelcome()

        # 登录ftp服务器，用户为非白名单用户
        fp = con_ftp.connect_ftp(self.host, self.port, self.case1_deny_user, self.password)
        log.warning('ftp非白名单用户{}结果为:{}'.format(self.case1_deny_user, fp))
        assert fp == 0

        # 检查ftp传输策略是否清空
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delftpcheck'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查FTP安全浏览策略是否清空')
        re = fun.wait_data(type=4, dut='gw', context=ftp_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) not in re

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='gw', type='ftp', flag=False)

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于多个用户白名单过滤的FTP传输策略')
    def test_ftp_check_user_a2(self):

        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='gw', type='ftp')

        log.warning('self.host, self.port, self.username, self.password:', self.host, self.port, self.username,
                    self.password)
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='ftpcheck', user_data=self.data2_check,
                                                        check_action=self.action), rbmDomain,
                 base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查ftp应用安全策略是否下发成功')
        re = fun.wait_data(type=4, dut='gw', context=ftp_ruleid)
        log.warning('预期包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) in re

        # 登录ftp服务器，用户为白名单用户
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('ftp第一个白名单用户{}欢迎语是：{}'.format(self.username, fp.getwelcome()))
        assert '220' in fp.getwelcome()

        fp = con_ftp.connect_ftp(self.host, self.port, self.case2_allow_user, self.password)
        log.warning('ftp第二个白名单用户{}欢迎语是：{}'.format(self.case2_allow_user, fp.getwelcome()))
        assert '220' in fp.getwelcome()

        # 登录ftp服务器，用户为非白名单用户
        fp = con_ftp.connect_ftp(self.host, self.port, self.case2_deny_user, self.password)
        log.warning('ftp非白名单用户{}结果为:{}'.format(self.case2_deny_user, fp))
        assert fp == 0

        # 检查ftp传输策略是否清空
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delftpcheck'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查FTP安全浏览策略是否清空')
        re = fun.wait_data(type=4, dut='gw', context=ftp_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) not in re

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='gw', type='ftp', flag=False)

    def teardown_class(self):
        # 回收环境
        # clr_env.clear_env()

        fun.rbm_close()
        fun.ssh_close('gw')
