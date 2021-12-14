'''
脚本一：
用例名称：验证隔离下基于下载扩展名白名单过滤的FTP传输策略
编写人员：李皖秋
编写日期：2021.7.15
测试目的：验证隔离下基于下载扩展名白名单过滤的FTP传输策略
测试步骤：
1、下发ftp的隔离代理：代理ip为前置机安全卡的ip，port为8887，等待nginx的24个进程起来
2、下发ftp的下载扩展名白名单：txt，等待nginx的24个进程起来
3、控制台走ftp隔离登录ftp服务器，下载文件扩展名为白名单txt，查看下载是否成功
4、控制台走ftp隔离登录ftp服务器，下载文件扩展名为非白名单pdf，查看下载是否成功
5、移除ftp的隔离策略，清空环境，等待nginx的24个进程起来
6、移除ftp传输策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/filter.json文件应该包含：allow-download和下载扩展名白名单：txt
3、下载成功
4、下载失败
5、cat /etc/jsac/customapp.stream应该不包含代理ip和port
6、cat /etc/jsac/filter.json文件应该不包含：ftp协议

脚本二：
用例名称：验证隔离下基于多个下载扩展名白名单过滤的FTP传输策略
编写人员：李皖秋
编写日期：2021.7.15
测试目的：验证隔离下基于多个下载扩展名白名单过滤的FTP传输策略
测试步骤：
1、下发ftp的隔离代理：代理ip为前置机安全卡的ip，port为8887，等待nginx的24个进程起来
2、下发ftp的下载扩展名白名单：txt、xls，等待nginx的24个进程起来
3、控制台走ftp隔离登录ftp服务器，下载文件扩展名为白名单txt，查看下载是否成功
4、控制台走ftp隔离登录ftp服务器，下载文件扩展名为白名单xls，查看下载是否成功
5、控制台走ftp隔离登录ftp服务器，下载文件扩展名为非白名单pdf，查看下载是否成功
6、移除ftp的隔离策略，清空环境，等待nginx的24个进程起来
7、移除ftp传输策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/filter.json文件应该包含：allow-download和下载扩展名白名单：txt、xls
3、下载成功
4、下载成功
5、下载失败
6、cat /etc/jsac/customapp.stream应该不包含代理ip和port
7、cat /etc/jsac/filter.json文件应该不包含：ftp协议
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
    from Case_rbm.iso_ftp_check_download import index
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
from data_check import con_ftp

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
ftp_ruleid = baseinfo.ftp_ruleid


class Test_iso_ftp_check_download():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')

    def teardown_method(self):
        clr_env.iso_teardown_met('ftp', base_path)
        clr_env.clear_datacheck('ftp', base_path)

        clr_env.iso_setup_class(dut='FrontDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        clr_env.iso_setup_class(dut='FrontDut')
        self.host = index.host
        self.port = index.port
        self.username = index.username
        self.password = index.password
        self.case1_deny_downfile = index.case1_deny_downfile
        self.case1_downremotePath = index.case1_downremotePath
        self.case1_downlocalPath = index.case1_downlocalPath
        self.case1_deny_downremotePath = index.case1_deny_downremotePath
        self.case1_deny_downlocalPath = index.case1_deny_downlocalPath

        self.check2_deny_download = index.check2_deny_download
        self.check2_allow_download = index.check2_allow_download
        self.case2_deny_downremotePath1 = index.case2_deny_downremotePath1
        self.case2_deny_downlocalPath1 = index.case2_deny_downlocalPath1
        self.case2_deny_downremotePath2 = index.case2_deny_downremotePath2
        self.case2_deny_downlocalPath2 = index.case2_deny_downlocalPath2
        self.case2_allow_downremotePath = index.case2_allow_downremotePath
        self.case2_allow_downlocalPath = index.case2_allow_downlocalPath

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下基于下载扩展名白名单过滤的FTP传输策略')
    def test_iso_ftp_check_download_a1(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='ftp')

        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='ftpcheck', download_data=self.case1_deny_downfile),
                 FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查ftp应用安全策略是否下发成功')
        re = fun.wait_data(type=4, dut='FrontDut', context=ftp_ruleid)
        log.warning('预期包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) in re

        # 登录ftp服务器，下载文件扩展名为非黑名单
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result1 = con_ftp.downFile(fp, self.case1_downremotePath, self.case1_downlocalPath)
        log.warning('ftp下载文件扩展名{}为非黑名单结果为:{}'.format(self.case1_downremotePath, result1))
        assert result1 == 1

        # 登录ftp服务器，下载文件扩展名为黑名单
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result2 = con_ftp.downFile(fp, self.case1_deny_downremotePath, self.case1_deny_downlocalPath)
        log.warning('ftp下载文件扩展名{}为黑名单结果为:{}'.format(self.case1_deny_downremotePath, result2))
        assert result2 == 0

        log.warning('清空ftp传输策略')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delftpcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查FTP安全浏览策略是否清空')
        re = fun.wait_data(type=4, dut='FrontDut', context=ftp_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) not in re

        log.warning('移除代理策略，清空环境')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        log.warning('检查代理策略是否移除成功')
        fun.check_proxy_policy(dut='FrontDut', type='ftp', flag=False)

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下基于多个下载扩展名白名单过滤的FTP传输策略')
    def test_iso_ftp_check_download_a2(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='ftp')

        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='ftpcheck', download_data=self.check2_deny_download),
                 FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查ftp应用安全策略是否下发成功')
        re = fun.wait_data(type=4, dut='FrontDut', context=ftp_ruleid)
        log.warning('预期包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) in re

        # 登录ftp服务器，下载文件扩展名为非黑名单
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result3 = con_ftp.downFile(fp, self.case2_allow_downremotePath, self.case2_allow_downlocalPath)
        log.warning('下载文件扩展名{}为非黑名单结果为:{}'.format(self.check2_allow_download, result3))
        assert result3 == 1

        # 登录ftp服务器，下载文件扩展名为第一个黑名单
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result1 = con_ftp.downFile(fp, self.case2_deny_downremotePath1, self.case2_deny_downlocalPath1)
        log.warning('ftp下载文件扩展名{}为第一个黑名单结果为:{}'.format(self.check2_deny_download[0], result1))
        assert result1 == 0

        # 登录ftp服务器，下载文件扩展名为第二个黑名单
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result2 = con_ftp.downFile(fp, self.case2_deny_downremotePath2, self.case2_deny_downlocalPath2)
        log.warning('ftp下载文件扩展名{}为第二个黑名单结果为:{}'.format(self.check2_deny_download[1], result2))
        assert result2 == 0

        log.warning('清空ftp传输策略')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delftpcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查FTP安全浏览策略是否清空')
        re = fun.wait_data(type=4, dut='FrontDut', context=ftp_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) not in re

        log.warning('移除代理策略，清空环境')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        log.warning('检查代理策略是否移除成功')
        fun.check_proxy_policy(dut='FrontDut', type='ftp', flag=False)

    def teardown_class(self):
        # 回收环境
        clr_env.iso_setup_class(dut='FrontDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')

