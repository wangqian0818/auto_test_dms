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
    from Case_rbm.mail_check_addr import index
    from common import fun, tool
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
from data_check import recv_pop3
from data_check import send_smtp

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
proxy_ip = baseinfo.gwClientIp
smtp_ip = baseinfo.smtp_ip
smtp_ruleid = baseinfo.smtp_ruleid


class Test_mail_check_addr():

    def setup_method(self):
        clr_env.data_check_setup_met()

    def teardown_method(self):
        clr_env.data_check_teardown_met('mail', base_path)

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.clr_env = clr_env
        self.action = index.action
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
        self.pop3_proxy_host = index.pop3_proxy_host
        self.pop3_proxy_port = index.pop3_proxy_port
        self.deny_mail = index.deny_mail
        self.deny_pwd = index.deny_pwd
        self.file = index.file
        self.attach_path = index.attach_path
        self.context = index.context
        self.title = index.title
        self.mail_sender = index.mail_sender
        self.mail_receiver = index.mail_receivers[0]

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于地址白名单过滤的邮件策略')
    def test_mail_check_addr_a1(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addsmtp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        smtp_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert smtp_res1 == 1
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addpop3'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        pop3_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert pop3_res1 == 1

        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='gw', type='smtp')
        fun.check_proxy_policy(dut='gw', type='pop3')

        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='mailcheck', mail_data=self.mail_sender,
                                                        check_action=self.action), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_check = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_check == 1

        log.warning('检查smtp应用安全策略是否下发成功')
        re = fun.wait_data(type=5, dut='gw', context=smtp_ruleid)
        log.warning('预期包含内容：{}'.format(smtp_ruleid))
        log.warning('查询mail.json命令返回值：\n{}'.format(re))
        assert str(smtp_ruleid) in re

        # 发送邮件,邮件地址为白名单地址【因为只有一个邮件地址在白名单中，所以发件人，收件人和抄送人都是同一个人】
        result1 = send_smtp.post_email(self.mail_sender, self.mail_user, self.mail_user, self.mail_user,
                                       self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
                                       self.attach_path, self.file, self.title, self.context, 0, 0)
        log.warning('白名单地址{}结果为:{}'.format(self.mail_sender, result1))
        assert result1 == 1

        # 发送邮件,邮件地址为非白名单地址
        result2 = send_smtp.post_email(self.deny_mail, self.mail_user, self.mail_user, self.mail_user,
                                       self.mail_host, self.mail_port, self.deny_mail, self.deny_pwd,
                                       self.attach_path, self.file, self.title, self.context, 0, 0)
        log.warning('非白名单地址{}结果为:{}'.format(self.deny_mail, result2))
        assert result2 == 0

        # 检查邮件策略是否清空
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delmailcheck'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_check = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_check == 1

        log.warning('检查邮件安全浏览策略是否清空')
        re = fun.wait_data(type=5, dut='gw', context=smtp_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(smtp_ruleid))
        log.warning('查询mail.json命令返回值：\n{}'.format(re))
        assert str(smtp_ruleid) not in re

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delsmtp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_smtp = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_smtp == 1
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delpop3'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_pop3 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_pop3 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='gw', type='smtp', flag=False)
        fun.check_proxy_policy(dut='gw', type='pop3', flag=False)

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于多个地址白名单过滤的邮件策略')
    def test_mail_check_addr_a2(self):
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addsmtp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        smtp_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert smtp_res1 == 1
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addpop3'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        pop3_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert pop3_res1 == 1

        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='gw', type='smtp')
        fun.check_proxy_policy(dut='gw', type='pop3')

        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='mailcheck', mail_data=self.mail_cc,
                                                        check_action=self.action), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_check = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_check == 1

        log.warning('检查smtp应用安全策略是否下发成功')
        re = fun.wait_data(type=5, dut='gw', context=smtp_ruleid)
        log.warning('预期包含内容：{}'.format(smtp_ruleid))
        log.warning('查询mail.json命令返回值：\n{}'.format(re))
        assert str(smtp_ruleid) in re

        log.warning('白名单地址发送邮件')
        result1 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
                                       self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
                                       self.attach_path, self.file, self.title, self.context, 0, 0)
        log.warning('白名单地址{}结果为:{}'.format(self.mail_sender, result1))
        assert result1 == 1

        log.warning('白名单地址接收邮件')
        log.warning('self.pop3_email:{}, self.pop3_pwd:{}, self.pop3_proxy_host:{}, self.pop3_proxy_port:{}'.format(
            self.pop3_email, self.pop3_pwd, self.pop3_proxy_host, self.pop3_proxy_port))
        msg = recv_pop3.get_email(self.pop3_email, self.pop3_pwd, self.pop3_proxy_host, self.pop3_proxy_port)
        mail_list = recv_pop3.print_info(msg)  # 解析
        assert self.title, self.context in mail_list
        log.warning('白名单接收者{}成功接收邮件'.format(self.pop3_email))

        log.warning('非白名单地址发送邮件')
        result2 = send_smtp.post_email(self.deny_mail, self.mail_receivers, self.mail_cc, self.mail_bcc, self.mail_host,
                                       self.mail_port, self.deny_mail, self.deny_pwd, self.attach_path, self.file,
                                       self.title, self.context, 0, 0)
        log.warning('非白名单地址{}结果为:{}'.format(self.deny_mail, result2))
        assert result2 == 0

        # 检查邮件策略是否清空
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delmailcheck'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_check = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_check == 1

        log.warning('检查邮件安全浏览策略是否清空')
        re = fun.wait_data(type=5, dut='gw', context=smtp_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(smtp_ruleid))
        log.warning('查询mail.json命令返回值：\n{}'.format(re))
        assert str(smtp_ruleid) not in re

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delsmtp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_smtp = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_smtp == 1
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delpop3'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_pop3 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_pop3 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='gw', type='smtp', flag=False)
        fun.check_proxy_policy(dut='gw', type='pop3', flag=False)

    #
    # def teardown_class(self):
    #     # 回收环境
    #     clr_env.clear_env()
    #
    #     fun.rbm_close()
    #     fun.ssh_close('gw')
