'''
脚本一：
用例名称：验证隔离下基于文件名过滤的邮件策略
编写人员：李皖秋
编写日期：2021.7.14
测试目的：验证隔离下基于文件名过滤的邮件策略
测试步骤：
1、下发邮件的隔离代理：代理ip为前置机安全卡的ip，port为8885（smtp）和8886（pop3），等待nginx的24个进程起来
2、下发黑名单附件名：test，等待nginx的24个进程起来
3、控制台发送邮件，邮件附件文件名为黑名单附件名：test，查看发送结果
4、控制台发送邮件，邮件附件文件名为非黑名单附件名：123，查看发送结果
5、接收邮件，查看pop3协议收到的邮件内容是否为非黑名单文件名发送的
6、移除邮件的隔离策略，清空环境，等待nginx的24个进程起来
7、移除邮件策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/filter.json文件应该包含：deny-basename和黑名单附件名：test
3、发送失败
4、发送成功
5、接收邮件内容为非黑名单文件名发送的
6、cat /etc/jsac/customapp.stream应该不包含代理ip和port
7、cat /etc/jsac/filter.json文件应该不包含：mail协议

脚本二：
用例名称：验证隔离下基于多个文件名过滤的邮件策略
编写人员：李皖秋
编写日期：2021.7.14
测试目的：验证隔离下基于多个文件名过滤的邮件策略
测试步骤：
1、下发邮件的隔离代理：代理ip为前置机安全卡的ip，port为8885（smtp）和8886（pop3），等待nginx的24个进程起来
2、下发黑名单附件名：test、juson，等待nginx的24个进程起来
3、控制台发送邮件，邮件附件文件名为黑名单附件名：test，查看发送结果
4、控制台发送邮件，邮件附件文件名为黑名单附件名：juson，查看发送结果
5、控制台发送邮件，邮件附件文件名为非黑名单附件名：123，查看发送结果
6、接收邮件，查看pop3协议收到的邮件内容是否为非黑名单文件名发送的
7、移除邮件的隔离策略，清空环境，等待nginx的24个进程起来
8、移除邮件策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/filter.json文件应该包含：deny-basename和黑名单附件名：test、juson
3、发送失败
4、发送失败
5、发送成功
6、接收邮件内容为非黑名单文件名发送的
7、cat /etc/jsac/customapp.stream应该不包含代理ip和port
8、cat /etc/jsac/filter.json文件应该不包含：mail协议
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
    from Case_rbm.iso_mail_check_filename import index
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


class Test_iso_mail_check_file():

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
        self.case1_step1 = index.case1_step1
        self.case1_step11 = index.case1_step11
        self.case1_step2 = index.case1_step2
        self.case2_step2 = index.case2_step2
        self.delcheck = index.delcheck
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
        self.context = index.context
        self.case1_title = index.case1_title
        self.case1_file1 = index.case1_file1
        self.case1_file2 = index.case1_file2
        self.case1_attach1 = index.case1_attach1
        self.case1_attach2 = index.case1_attach2
        self.case2_title = index.case2_title
        self.case2_file1 = index.case2_file1
        self.case2_file2 = index.case2_file2
        self.case2_file3 = index.case2_file3
        self.case2_attach1 = index.case2_attach1
        self.case2_attach2 = index.case2_attach2
        self.case2_attach3 = index.case2_attach3

        self.case1_filename = index.case1_filename
        self.case2_filename = index.case2_filename
        self.case2_deny_file = index.case2_deny_file

    @allure.feature('验证隔离下基于文件名过滤的邮件策略')
    def test_iso_mail_check_file_a1(self):

        # 下发配置
        log.warning(
            '1、下发邮件的隔离代理：代理ip为前置机安全卡的ip，port为8885（smtp）和8886（pop3），等待nginx的24个进程起来；cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口')
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
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step11[key][1] in re

        log.warning('2、下发黑名单附件名：test，等待nginx的24个进程起来')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='mailcheck', attachment_name_data=f'{self.case1_filename}'),
                 FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_check = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_check == 1
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'FrontDut', self.case1_step2[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step2[key][1] in re

        # 发送邮件,邮件地址为黑名单文件名
        log.warning('3、控制台发送邮件，邮件附件文件名为黑名单附件名：test，查看发送结果；发送失败')
        result1 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
                                       self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
                                       self.case1_attach1, self.case1_file1, self.case1_title, self.context, 0, 1)
        log.warning('黑名单文件名{}结果为:{}'.format(self.case1_file1, result1))
        assert result1 == 0

        # 发送邮件,邮件地址为非黑名单文件名
        log.warning('4、控制台发送邮件，邮件附件文件名为非黑名单附件名：123，查看发送结果；发送成功')
        result2 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
                                       self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
                                       self.case1_attach2, self.case1_file2, self.case1_title, self.context, 0, 1)
        log.warning('非黑名单文件名{}结果为:{}'.format(self.case1_file2, result2))
        assert result2 == 1

        # 接收邮件
        log.warning('5、接收邮件，查看pop3协议收到的邮件内容是否为非黑名单文件名发送的；接收邮件内容为非黑名单文件名发送的')
        msg = recv_pop3.get_email(self.pop3_email, self.pop3_pwd, self.pop3_proxy_host, self.pop3_proxy_port)
        mail_list = recv_pop3.print_info(msg)  # 解析
        assert self.case1_title, self.context in mail_list

        # 移除策略，还原环境
        log.warning('6、移除邮件的隔离策略，清空环境，等待nginx的24个进程起来')
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
        # 检查策略移除是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100, flag='不存在')
            log.warning(re)
            assert self.case1_step1[key][1] not in re

        # 检查邮件策略是否清空
        log.warning('7、移除邮件策略，等待nginx的24个进程起来')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delmailcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_check = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_check == 1
        for key in self.delcheck:
            re = fun.wait_data(self.delcheck[key][0], 'FrontDut', self.delcheck[key][1], '配置', 100, flag='不存在')
            assert self.delcheck[key][1] not in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下基于多个文件名过滤的邮件策略')
    def test_iso_mail_check_file_a2(self):

        # 下发配置
        log.warning(
            '1、下发邮件的隔离代理：代理ip为前置机安全卡的ip，port为8885（smtp）和8886（pop3），等待nginx的24个进程起来；cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口')
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
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step11[key][1] in re

        log.warning('2、下发黑名单附件名：test、juson，等待nginx的24个进程起来')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='mailcheck',
                                            attachment_name_data=f'{self.case2_filename};{self.case2_deny_file}'),
                 FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_check = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_check == 1
        for key in self.case2_step2:
            re = fun.wait_data(self.case2_step2[key][0], 'FrontDut', self.case2_step2[key][1], '配置', 100)
            log.warning(re)
            assert self.case2_step2[key][1] in re

        # 发送邮件,邮件地址为黑名单文件名
        log.warning('3、控制台发送邮件，邮件附件文件名为黑名单附件名：test，查看发送结果；发送失败')
        result1 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
                                       self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
                                       self.case2_attach1, self.case2_file1, self.case2_title, self.context, 0, 1)
        log.warning('第一个黑名单文件名{}结果为:{}'.format(self.case2_file1, result1))
        assert result1 == 0

        log.warning('4、控制台发送邮件，邮件附件文件名为黑名单附件名：juson，查看发送结果；发送失败')
        result2 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
                                       self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
                                       self.case2_attach2, self.case2_file2, self.case2_title, self.context, 0, 1)
        log.warning('第二个黑名单文件名{}结果为:{}'.format(self.case2_file2, result2))
        assert result2 == 0

        # 发送邮件,邮件地址为非黑名单文件名
        log.warning('5、控制台发送邮件，邮件附件文件名为非黑名单附件名：123，查看发送结果；发送成功')
        result3 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
                                       self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
                                       self.case2_attach3, self.case2_file3, self.case2_title, self.context, 0, 1)
        log.warning('非黑名单文件名{}结果为:{}'.format(self.case2_file3, result3))
        assert result3 == 1

        # 接收邮件
        log.warning('6、接收邮件，查看pop3协议收到的邮件内容是否为非黑名单文件名发送的；接收邮件内容为非黑名单文件名发送的')
        msg = recv_pop3.get_email(self.pop3_email, self.pop3_pwd, self.pop3_proxy_host, self.pop3_proxy_port)
        mail_list = recv_pop3.print_info(msg)  # 解析
        assert self.case2_title, self.context in mail_list

        # 移除策略，还原环境
        log.warning('7、移除邮件的隔离策略，清空环境，等待nginx的24个进程起来')
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
        # 检查策略移除是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100, flag='不存在')
            log.warning(re)
            assert self.case1_step1[key][1] not in re

        # 检查邮件策略是否清空
        log.warning('8、移除邮件策略，等待nginx的24个进程起来')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delmailcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_check = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_check == 1
        for key in self.delcheck:
            re = fun.wait_data(self.delcheck[key][0], 'FrontDut', self.delcheck[key][1], '配置', 100, flag='不存在')
            assert self.delcheck[key][1] not in re

    def teardown_class(self):
        # 回收环境
        clr_env.iso_setup_class(dut='FrontDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')

