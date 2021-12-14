'''
脚本一：
用例名称：验证隔离下基于多种过滤方法过滤的邮件策略
编写人员：李皖秋
编写日期：2021.7.14
测试目的：验证隔离下基于多种过滤方法过滤的邮件策略
测试步骤：
1、下发邮件的隔离代理：代理ip为前置机安全卡的ip，port为8885（smtp）和8886（pop3），等待nginx的24个进程起来
2、下发地址白名单：autotest_send@jusontech.com、autotest_recv@jusontech.com；黑名单主题：test；黑名单文件名：test；附件扩展名黑名单：txt，等待nginx的24个进程起来
3、控制台发送邮件，邮件地址为非白名单地址：jusontest@163.com，查看发送结果
4、控制台发送邮件，邮件主题为黑名单主题：test，查看发送结果
5、控制台发送邮件，邮件附件文件名为黑名单文件名：test，查看发送结果
6、控制台发送邮件，邮件附件扩展名为黑名单扩展名：txt，查看发送结果
7、控制台发送邮件，邮件地址为白名单地址：autotest_send@jusontech.com；非黑名单主题：我不是黑名单主题，测试多种类型（隔离的数据结构检查）；附件文件名为非黑名单：1；附件扩展名为非黑名单：xls，查看发送结果
8、接收邮件，接收邮件地址为白名单地址：autotest_recv@jusontech.com，查看pop3协议收到的邮件内容是否为刚刚发送的
9、移除邮件的隔离策略，清空环境，等待nginx的24个进程起来
10、移除邮件策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/filter.json文件应该包含：allow-from、deny-topic、deny-basename、deny-suffix和地址白名单：autotest_send@jusontech.com、autotest_recv@jusontech.com；黑名单主题：test；黑名单文件名：test；附件扩展名黑名单：txt
3、发送失败
4、发送失败
5、发送失败
6、发送失败
7、发送成功
8、接收邮件内容为非黑名单扩展名发送的
9、cat /etc/jsac/customapp.stream应该不包含代理ip和port
10、cat /etc/jsac/filter.json文件应该不包含：mail协议
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
    from Case_rbm.iso_mail_check_alltype import index
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
from data_check import recv_pop3
from data_check import send_smtp

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
FrontDomain = baseinfo.BG8010FrontDomain

proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
smtp_ruleid = baseinfo.smtp_ruleid


class Test_iso_mail_check_alltype():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')

    def teardown_method(self):
        clr_env.iso_teardown_met('mail', base_path)
        clr_env.clear_datacheck('mail', base_path)

        clr_env.iso_setup_class(dut='FrontDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        clr_env.iso_setup_class(dut='FrontDut')
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
        self.context = index.context
        self.deny_title = index.deny_title
        self.title = index.title
        self.deny_name_file = index.deny_name_file
        self.deny_extend_file = index.deny_extend_file
        self.file = index.file
        self.attach_file = index.attach_file
        self.attach_extend = index.attach_extend
        self.attach_path = index.attach_path

        self.mail_sender = index.mail_sender
        self.mail_receiver = index.mail_receivers[0]
        self.deny_title = index.deny_title
        self.deny_filename = index.deny_filename
        self.deny_extend = index.deny_extend

    @allure.feature('验证隔离下基于多种过滤方法过滤的邮件策略')
    def test_iso_mail_check_alltype_a1(self):

        # 下发配置
        log.warning('下发邮件的隔离代理')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addsmtp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addpop3_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res2 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res2 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res2 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='smtp')
        fun.check_proxy_policy(dut='FrontDut', type='pop3')


        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='mailcheck', ruleid=103,
                                                        mail_data=f"{self.mail_sender};{self.mail_receiver}",
                                                        check_action='allow'),
                 FrontDomain, base_path)
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='mailcheck', subject_data=self.deny_title,
                                                        attachmentExt_data=self.deny_extend), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_check = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_check == 1

        log.warning('检查smtp应用安全策略是否下发成功')
        re = fun.wait_data(type=5, dut='FrontDut', context=smtp_ruleid)
        log.warning('预期包含内容：{}'.format(smtp_ruleid))
        log.warning('查询mail.json命令返回值：\n{}'.format(re))
        assert str(smtp_ruleid) in re

        # 1、发送邮件,邮件地址为非白名单地址
        result1 = send_smtp.post_email(self.deny_mail, self.mail_receivers, self.mail_cc, self.mail_bcc, self.mail_host,
                                       self.mail_port, self.deny_mail, self.deny_pwd, self.attach_path,
                                       self.deny_name_file, self.title, self.context, 0, 1)
        log.warning('非白名单地址{}结果为:{}'.format(self.deny_mail, result1))
        assert result1 == 0

        # 2、发送邮件,黑名单主题+黑名单后缀名
        result2 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
                                       self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
                                       self.attach_extend, self.deny_extend_file, self.deny_title, self.context, 0, 1)
        log.warning('黑名单主题{}+黑名单后缀名{}，结果为:{}'.format(self.deny_title, self.deny_extend, result2))
        assert result2 == 0

        # # 3、发送邮件,邮件地址为黑名单文件名
        # result3 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
        #                                self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
        #                                self.attach_file, self.deny_name_file, self.title, self.context, 0, 1)
        # log.warning('黑名单文件名{}结果为:{}'.format(self.deny_name_file, result3))
        # assert result3 == 0

        # 5、发送邮件,邮件地址为白名单地址、非黑名单主题、非黑名单文件名、非黑名单文件扩展名
        result5 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
                                       self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
                                       self.attach_path, self.file, self.title, self.context, 0, 1)
        log.warning('各种参数均为白名单和非黑名单结果为:{}'.format(result5))
        assert result5 == 1

        # 接收邮件
        msg = recv_pop3.get_email(self.pop3_email, self.pop3_pwd, self.pop3_proxy_host, self.pop3_proxy_port)
        mail_list = recv_pop3.print_info(msg)  # 解析
        assert self.title, self.context in mail_list

        # 检查邮件策略是否清空
        log.warning('10、移除邮件策略，等待nginx的24个进程起来')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delmailcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_check = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_check == 1

        log.warning('检查邮件安全浏览策略是否清空')
        re = fun.wait_data(type=5, dut='FrontDut', context=smtp_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(smtp_ruleid))
        log.warning('查询mail.json命令返回值：\n{}'.format(re))
        assert str(smtp_ruleid) not in re

        # 移除策略，还原环境
        log.warning('9、移除邮件的隔离策略，清空环境，等待nginx的24个进程起来')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delsmtp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res1 == 1
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delpop3_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res2 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res2 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res2 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='FrontDut', type='smtp', flag=False)
        fun.check_proxy_policy(dut='FrontDut', type='pop3', flag=False)

    def teardown_class(self):
        # 回收环境
        clr_env.iso_setup_class(dut='FrontDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')

