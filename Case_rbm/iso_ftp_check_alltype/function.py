'''
脚本一：
用例名称：验证隔离下基于多种过滤方法过滤的FTP传输策略
编写人员：李皖秋
编写日期：2021.7.15
测试目的：验证隔离下基于多种过滤方法过滤的FTP传输策略
测试步骤：
1、下发ftp的隔离代理：代理ip为前置机安全卡的ip，port为8887，等待nginx的24个进程起来
2、下发ftp的用户白名单：test；上传文件扩展名白名单：txt；下载文件扩展名白名单：txt；命令控制白名单：不包含RETR，等待nginx的24个进程起来
3、控制台走ftp隔离登录ftp服务器，登录用户为白名单test，查看登录是否成功
4、控制台走ftp隔离登录ftp服务器，登录用户为非白名单lwq，查看登录是否成功
5、控制台走ftp隔离登录ftp服务器，上传文件扩展名为白名单txt，查看文件是否上传成功
6、控制台走ftp隔离登录ftp服务器，上传文件扩展名为非白名单pdf，查看文件是否上传成功
7、控制台走ftp隔离登录ftp服务器，下载文件扩展名为白名单txt（下载命令被禁止），查看文件是否下载成功
8、控制台走ftp隔离登录ftp服务器，下载文件扩展名为非白名单pdf（下载命令被禁止），查看文件是否下载成功
9、移除ftp的隔离策略，清空环境，等待nginx的24个进程起来
10、移除ftp传输策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/filter.json文件应该包含：allow-user、allow-upload、allow-download、allow-cmd，用户白名单test、下载扩展名白名单txt，上传扩展名白名单txt，以及不包含命令RETR
3、登录成功
4、登录失败
5、上传成功
6、上传失败
7、下载失败
8、下载失败
9、cat /etc/jsac/customapp.stream应该不包含代理ip和port
10、cat /etc/jsac/filter.json文件应该不包含：ftp协议
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
    from Case_rbm.iso_ftp_check_alltype import index
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


class Test_iso_ftp_check_alltype():

    # def setup_method(self):
    #     clr_env.data_check_setup_met(dut='FrontDut')
    #     clr_env.data_check_setup_met(dut='BackDut')
    #
    # def teardown_method(self):
    #     clr_env.iso_teardown_met('ftp', base_path)
    #     clr_env.clear_datacheck('ftp', base_path)
    #
    #     clr_env.iso_setup_class(dut='FrontDut')
    #     clr_env.iso_setup_class(dut='BackDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        self.host = index.proxy_ip
        self.port = index.port
        self.username = baseinfo.ftp_user
        self.password = baseinfo.ftp_pass
        self.deny_user = index.deny_user
        self.deny_action = index.deny_action
        self.allow_action = index.allow_action
        self.check_deny = index.check_deny
        self.check_allow = index.check_allow
        self.case_upremotePath = index.case_upremotePath
        self.case_uplocalPath = index.case_uplocalPath
        self.case_deny_upremotePath = index.case_deny_upremotePath
        self.case_deny_uplocalPath = index.case_deny_uplocalPath
        self.case_downremotePath = index.case_downremotePath
        self.case_downlocalPath = index.case_downlocalPath
        self.case_deny_downremotePath = index.case_deny_downremotePath
        self.case_deny_downlocalPath = index.case_deny_downlocalPath

        # clr_env.iso_setup_class(dut='FrontDut')

    @allure.feature('验证隔离下基于多种过滤方法过滤的FTP传输策略【禁止上传PDF】')  # 原本只有这一个用例，后面需要补充
    def test_iso_ftp_check_alltype_deny_pdf(self):
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

        log.warning(
            'self.host:{}, self.port:{}, self.username:{}, self.password:{}'.format(self.host, self.port, self.username,
                                                                                    self.password))
        cmd = "ABOR;ACCT;ADAT;ALLO;APPE;AUTH;CCC;CDUP;CONF;CWD;DELE;ENC;EPRT;EPSV;FEAT;HELP;LANG;LIST;LPRT;LPSV;MDTM;" \
              "MIC;MKD;MLSD;MLST;MODE;NLST;NOOP;OPTS;PASS;PASV;PBSZ;PORT;PROT;PWD;QUIT;REIN;REST;RMD;RNFR;RNTO;SITE;" \
              "SIZE;SMNT;STAT;STOR;STOU;STRU;SYST;TYPE;USER;XCUP;XMKD;XPWD;XRCP;XRMD;XRSQ;XSEM;XSEN;RMD;STOR;RETR"
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='ftpcheck', user_data=self.username, cmd_data=cmd,
                                                        check_action=self.allow_action), FrontDomain, base_path)
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='ftpcheck', ruleid=107, upload_data=self.check_deny,
                                                        check_action=self.deny_action),
                 FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查ftp应用安全策略是否下发成功')
        re = fun.wait_data(type=4, dut='FrontDut', context=ftp_ruleid)
        log.warning('预期包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) in re

        # 1、登录ftp服务器，用户为白名单用户
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        assert '220' in fp.getwelcome()

        # 2、登录ftp服务器，用户为非白名单用户
        fp2 = con_ftp.connect_ftp(self.host, self.port, self.deny_user, self.password)
        log.warning('ftp非白名单用户{}结果为:{}'.format(self.deny_user, fp2))
        assert fp2 == 0

        # 3、登录ftp服务器，上传文件扩展名为非黑名单
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        log.warning('ftp上传路径为：{}'.format(self.case_upremotePath))
        result1 = con_ftp.uploadFile(fp, self.case_upremotePath, self.case_uplocalPath)
        log.warning('ftp上传文件扩展名{}为非黑名单结果为:{}'.format(self.case_uplocalPath, result1))
        assert result1 == 1

        # 4、登录ftp服务器，上传文件扩展名为黑名单
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result2 = con_ftp.uploadFile(fp, self.case_deny_upremotePath, self.case_deny_uplocalPath)
        log.warning('ftp上传文件扩展名{}为黑名单结果为:{}'.format(self.case_deny_uplocalPath, result2))
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
    #
    # def teardown_class(self):
    #     # 回收环境
    #     clr_env.iso_setup_class(dut='FrontDut')
    #     clr_env.iso_setup_class(dut='BackDut')
    #
    #     fun.rbm_close()
    #     fun.ssh_close('FrontDut')
