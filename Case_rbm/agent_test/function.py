#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/10/29 16:26
try:
    import sys, allure, pytest, logging
    log = logging.getLogger(__name__)
except Exception as err:
    print('导入CPython内置函数库失败!错误信息如下:')
    print(err)
    sys.exit(0)

from common import baseinfo, fun, tool
from common import clr_env
from common.rabbitmq import *
from data_check import http_check, con_ftp, send_smtp

base_path = os.path.dirname(os.path.abspath(__file__))  # 获取当前项目文件夹
base_path = base_path.replace('\\', '/')
sys.path.insert(0, base_path)  # 将当前目录添加到系统环境变量,方便下面导入版本配置等文件

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
url = baseinfo.http_proxy_url
http_content = baseinfo.http_content

ftp_user = baseinfo.ftp_user
ftp_pass = baseinfo.ftp_pass
ftp_proxy_port = baseinfo.ftp_proxy_port

# smtp相关参数设置
mail_sender = baseinfo.mail_sender  # 发件人
mail_receivers = baseinfo.mail_receivers  # 收件人
mail_cc = baseinfo.mail_cc  # 抄送人
mail_bcc = baseinfo.mail_bcc  # 暗送人
mail_port = baseinfo.smtp_proxy_port  # 设置服务器端口
mail_user = baseinfo.mail_user  # 邮件登录地址
mail_pass = baseinfo.mail_pass  # 授权码

# pop3相关参数设置
# 获取邮箱密码和对应邮箱POP3服务器,邮件地址跟收件人相同
pop3_email = baseinfo.pop3_email
pop3_pwd = baseinfo.pop3_pwd  # 授权码
pop3_proxy_port = baseinfo.pop3_proxy_port

mail_attach = baseinfo.mail_attach
title = '关于mail代理_连通性测试_新管控'
context = '测试内容-content'
file = '1.xls'
attach_path = mail_attach + file

proxy_ip = baseinfo.gwClientIp
http_proxy_ip = baseinfo.http_proxy_ip
ftp_proxy_ip = baseinfo.gwClientIp
smtp_proxy_ip = baseinfo.smtp_proxy_ip
pop3_proxy_ip = baseinfo.pop3_proxy_ip


# 测试三种代理策略的下发，联通性和移除是否正常
class Test_agent():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.clr_env = clr_env

        clr_env.clear_env()

    def setup_method(self):
        clr_env.data_check_setup_met()


    # @pytest.mark.skip(reseason="skip")
    def test_http_agent(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理端口是否监听
        re = fun.wait_data(type=1, dut='gw', context=http_proxy_ip)
        log.warning('预期包含内容：{}'.format(http_proxy_ip))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert http_proxy_ip in re
        # 检查代理文件是否存在，内容是否正确
        cmd = fun.get_proxyfile_cmd(type='http')
        re1 = fun.cmd(cmd=cmd, domain='gw')
        log.warning('代理文件内容为：' + re1)
        assert http_proxy_ip in re1

        # 发送get请求，不包含黑名单内容的普通请求
        status_code = http_check.http_get(url, flag=1)
        log.warning('get普通请求的请求内容为：{}'.format(status_code))
        assert status_code == 200

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1

        # 检查代理是否成功移除：代理端口是否没有监听
        re = fun.wait_data(type=1, dut='gw', context=http_proxy_ip, flag=False)
        log.warning('预期不包含内容：{}'.format(http_proxy_ip))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert http_proxy_ip not in re

        # 检查代理文件是否存在，内容是否正确
        cmd = fun.get_proxyfile_cmd(type='http')
        re1 = fun.cmd(cmd=cmd, domain='gw')
        log.warning('代理文件内容为：' + re1)
        assert http_proxy_ip not in re1

    # @pytest.mark.skip(reseason="skip")
    def test_ftp_agent(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理端口是否监听
        re = fun.wait_data(dut='gw', context=ftp_proxy_ip, type=1)
        log.warning('预期包含内容：{}'.format(ftp_proxy_ip))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert ftp_proxy_ip in re
        # 检查代理文件是否存在，内容是否正确
        cmd = fun.get_proxyfile_cmd(type='ftp')
        re1 = fun.cmd(cmd=cmd, domain='gw')
        log.warning('代理文件内容为：' + re1)
        assert ftp_proxy_ip in re1

        # 登录ftp服务器
        fp = con_ftp.connect_ftp(proxy_ip, ftp_proxy_port, ftp_user, ftp_pass)
        log.warning('ftp欢迎语是：{}'.format(fp.getwelcome()))
        assert '220' in fp.getwelcome()

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1

        # 检查代理文件是否存在，内容是否正确
        cmd = fun.get_proxyfile_cmd(type='ftp')
        re1 = fun.cmd(cmd=cmd, domain='gw')
        log.warning('代理文件内容为：' + re1)
        assert ftp_proxy_ip not in re1

        # 检查代理是否成功移除：代理端口是否没有监听
        re = fun.wait_data(type=1, dut='gw', context=ftp_proxy_ip, flag=False)
        log.warning('预期不包含内容：{}'.format(ftp_proxy_ip))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert ftp_proxy_ip not in re

    # @pytest.mark.skip(reseason="skip")
    def test_mail_agent(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addsmtp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addpop3'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1
        # 检查代理端口是否监听
        re = fun.wait_data(dut='gw', context=smtp_proxy_ip, type=1)
        log.warning('预期包含内容：{}'.format(smtp_proxy_ip))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert smtp_proxy_ip in re
        re = fun.wait_data(dut='gw', context=pop3_proxy_ip, type=1)
        log.warning('预期包含内容：{}'.format(pop3_proxy_ip))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert pop3_proxy_ip in re
        # 检查代理文件是否存在，内容是否正确
        cmd = fun.get_proxyfile_cmd(type='smtp')
        re1 = fun.cmd(cmd=cmd, domain='gw')
        log.warning('代理文件内容为：' + re1)
        assert smtp_proxy_ip in re1
        cmd = fun.get_proxyfile_cmd(type='pop3')
        re1 = fun.cmd(cmd=cmd, domain='gw')
        log.warning('代理文件内容为：' + re1)
        assert pop3_proxy_ip in re1

        # 发送邮件,邮件地址为白名单地址
        result1 = send_smtp.post_email(mail_sender, mail_receivers, mail_cc, mail_bcc,
                                       proxy_ip, mail_port, mail_user, mail_pass,
                                       attach_path, file, title, context, 0, 0)
        log.warning('邮件{}发送邮件的结果为:{}'.format(mail_sender, result1))
        assert result1 == 1

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delsmtp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_smtp = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_smtp == 1
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delpop3'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_pop3 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_pop3 == 1

        # 检查代理文件是否存在，内容是否正确
        cmd = fun.get_proxyfile_cmd(type='smtp')
        re1 = fun.cmd(cmd=cmd, domain='gw')
        log.warning('代理文件内容为：' + re1)
        assert smtp_proxy_ip not in re1
        cmd = fun.get_proxyfile_cmd(type='pop3')
        re1 = fun.cmd(cmd=cmd, domain='gw')
        log.warning('代理文件内容为：' + re1)
        assert pop3_proxy_ip not in re1

        # 检查代理是否成功移除：代理端口是否没有监听
        re = fun.wait_data(type=1, dut='gw', context=smtp_proxy_ip, flag=False)
        log.warning('预期不包含内容：{}'.format(smtp_proxy_ip))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert smtp_proxy_ip not in re
        re = fun.wait_data(type=1, dut='gw', context=pop3_proxy_ip, flag=False)
        log.warning('预期不包含内容：{}'.format(pop3_proxy_ip))
        log.warning('监听端口命令返回值：\n{}'.format(re))
        assert pop3_proxy_ip not in re

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
