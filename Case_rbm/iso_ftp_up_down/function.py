# encoding='utf-8'
from data_check import send_smtp, recv_pop3, con_ftp

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
    from Case_rbm.iso_ftp_up_down import index
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

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
http_content = baseinfo.http_content
BG8010ServerPwd = baseinfo.BG8010ServerPwd
ssh_proxy_port = baseinfo.ssh_proxy_port


class Test_iso_ftp_up_down():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')

    def teardown_method(self):
        clr_env.iso_setup_class(dut='FrontDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        fun.ssh_BG8010Client.connect()
        fun.ssh_BG8010Server.connect()
        self.mail_sender = index.mail_sender
        self.mail_receivers = index.mail_receivers
        self.mail_cc = index.mail_cc
        self.mail_bcc = index.mail_bcc
        self.mail_host = index.mail_host
        self.mail_port = index.mail_port
        self.mail_user = index.mail_user
        self.mail_pass = index.mail_pass
        self.pop3_email = index.pop3_email
        self.pop3_pwd = index.pop3_pwd
        self.pop3_proxy_port = index.pop3_proxy_port
        self.title = index.title
        self.file = index.file
        self.attach_path = index.attach_path
        self.context = index.context
        self.ftp_proxy_port = index.ftp_proxy_port
        self.ftp_user = index.ftp_user
        self.ftp_pass = index.ftp_pass
        self.case2_downremotePath = index.case2_downremotePath
        self.case2_downlocalPath = index.case2_downlocalPath
        self.upremotePath = index.upremotePath
        self.uplocalPath = index.uplocalPath

        clr_env.iso_setup_class(dut='FrontDut')

    @pytest.mark.skip(reseason="skip")     # 邮件模块，暂未调试
    @allure.feature('验证隔离下的邮件代理策略发送50M大小的附件')
    def test_iso_ftp_up_down_a1(self):


        # # 发送邮件，检测隔离代理是否生效
        # log.warning('--------------------准备发送邮件，检测隔离代理是否生效-------------------------')
        # result = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
        #                                self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
        #                                self.attach_path, self.file, self.title, self.context, 0, 1)
        # log.warning('隔离下的邮件代理结果为:{}'.format(result))
        # assert result == 1
        #
        # # 接收邮件
        # log.warning('-------------------------准备接收邮件----------------------------------')
        # msg = recv_pop3.get_email(self.pop3_email, self.pop3_pwd, proxy_ip, self.pop3_proxy_port)
        # log.warning('pop3获取邮件返回的内容是：'.format(msg))
        # mail_list = recv_pop3.print_info(msg)  # 解析
        # log.warning('接收邮件解析到的列表为{}'.format(mail_list))
        # assert self.title, self.context in mail_list

        # 移除策略，清空环境
        log.warning('-------------------------准备移除策略，清空环境----------------------------------')



    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的ftp传输策略下载一个100M大小的文件')
    def test_iso_ftp_up_down_a2(self):

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

        # 登录ftp服务器，下载一个100M大小的文件
        fp = con_ftp.connect_ftp(proxy_ip, self.ftp_proxy_port, self.ftp_user, self.ftp_pass)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result = con_ftp.downFile(fp, self.case2_downremotePath, self.case2_downlocalPath)
        log.warning('ftp走隔离下载一个100M大小的文件结果为:{}'.format(result))
        assert result == 1

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
    @allure.feature('验证隔离下的ftp传输策略上传一个100M大小的文件')
    def test_iso_ftp_up_down_a3(self):

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

        # 登录ftp服务器，上传一个100M大小的文件
        fp = con_ftp.connect_ftp(proxy_ip, self.ftp_proxy_port, self.ftp_user, self.ftp_pass)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result = con_ftp.uploadFile(fp, self.upremotePath, self.uplocalPath)
        log.warning('ftp走隔离上传一个100M大小的文件结果为:{}'.format(self.uplocalPath, result))
        assert result == 1

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
    def teardown_class(self):
        # 回收环境
        # clr_env.iso_teardown_met('mail', base_path)
        clr_env.iso_teardown_met('ftp', base_path)
        clr_env.iso_setup_class(dut='FrontDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')

