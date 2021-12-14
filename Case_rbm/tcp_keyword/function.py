# encoding='utf-8'
from common.baseinfo import pop3_appid
from data_check import con_ftp, http_check, send_smtp, recv_pop3

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
    from Case_rbm.tcp_keyword import index
    from common import fun, tool, clr_env
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
from common.rabbitmq import *

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
proxy_ip = baseinfo.gwClientIp
rbmExc = baseinfo.rbmExc
http_url = baseinfo.http_proxy_url
http_content = baseinfo.http_content
ssh_proxy_port = baseinfo.ssh_proxy_port
smtp_appid = baseinfo.smtp_appid
ftp_appid = baseinfo.ftp_appid
tcp_appid = baseinfo.tcp_appid
mail_sender = baseinfo.mail_sender
mail_receivers = baseinfo.mail_receivers
mail_cc = baseinfo.mail_cc
mail_bcc = baseinfo.mail_bcc
mail_port = baseinfo.smtp_proxy_port
mail_user = baseinfo.mail_user
mail_pass = baseinfo.mail_pass
pop3_email = baseinfo.pop3_email
pop3_pwd = baseinfo.pop3_pwd
pop3_proxy_port = baseinfo.pop3_proxy_port
ftp_proxy_port = baseinfo.ftp_proxy_port
ftp_user = baseinfo.ftp_user
ftp_pass = baseinfo.ftp_pass


class Test_iso_tcp_keyword():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='gw')

    def teardown_method(self):
        fun.send(rbmExc, tool.interface().keyword_interface(appid=smtp_appid, ruleid=4), rbmDomain, base_path)
        fun.send(rbmExc, tool.interface().keyword_interface(appid=pop3_appid, ruleid=1), rbmDomain, base_path)
        fun.send(rbmExc, tool.interface().keyword_interface(appid=ftp_appid, ruleid=self.ftp_ruleid), rbmDomain,
                 base_path)
        fun.send(rbmExc, tool.interface().keyword_interface(appid=tcp_appid, ruleid=self.tcp_ruleid), rbmDomain,
                 base_path)

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.mail_ruleid = index.mail_ruleid
        self.title = index.title
        self.context = index.context
        self.title_juson = index.title_juson
        self.context_tech = index.context_tech
        self.juson_file_path = index.juson_file_path
        self.tech_file_path = index.tech_file_path
        self.filename_keyword = index.filename_keyword
        self.juson_keyword = index.juson_keyword
        self.tech_keyword = index.tech_keyword
        self.smtp_keyword = index.smtp_keyword
        self.pop3_keyword = index.pop3_keyword
        self.juson_base64 = index.juson_base64
        self.tech_base64 = index.tech_base64
        self.smtp_keyword_base64 = index.smtp_keyword_base64
        self.pop3_keyword_base64 = index.pop3_keyword_base64
        self.file_juson = index.file_juson
        self.file_tech = index.file_tech

        self.ftp_ruleid = index.ftp_ruleid
        self.ftp_keyword1 = index.ftp_keyword1
        self.ftp_keyword2 = index.ftp_keyword2
        self.case2_downremotePath = index.case2_downremotePath
        self.case2_downlocalPath = index.case2_downlocalPath
        self.case2_upremotePath = index.case2_upremotePath
        self.case2_uplocalPath = index.case2_uplocalPath
        self.tcp_ruleid = index.tcp_ruleid
        self.tcp_keyword1 = index.tcp_keyword1
        self.tcp_keyword2 = index.tcp_keyword2
        self.allow_file = index.allow_file
        self.deny_file = index.deny_file
        self.allow_url = index.allow_url
        self.deny_url = index.deny_url

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的tcp策略（http方式验证）')
    def test_tcp_keyword(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='add_tcp_http'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        res = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process', name='前置机nginx进程')
        assert res == 1

        # 检查代理策略是否下发成功
        fun.check_proxy_policy(type='tcp')

        # 下发关键字过滤策略
        fun.send(rbmExc, tool.interface().keyword_interface(appid=tcp_appid, ruleid=self.tcp_ruleid,
                                                            pattern=f'{self.tcp_keyword1};{self.tcp_keyword2}'),
                 rbmDomain, base_path)
        log.warning('检查内容审查策略是否下发成功')
        rule_list = self.tcp_ruleid.split(';')
        re = fun.wait_data(type=8, dut='gw')
        log.warning('预期包含内容：{}'.format(rule_list))
        log.warning('查询keyword.json命令返回值：\n{}'.format(re))
        assert rule_list[0], rule_list[1] in re

        # 发送get请求，验证正常请求是否成功
        log.warning('请求地址为{}'.format(http_url))
        content = http_check.http_get(http_url)
        log.warning('get请求返回的内容为：{}'.format(content))
        assert content == http_content

        time.sleep(10)
        # 发送post请求，包含关键字过滤为post的请求应该被禁止
        log.warning('请求地址为{}'.format(http_url))
        status_code = http_check.http_post(http_url)
        log.warning('包含关键字过滤为post的请求返回的状态码为：{}'.format(status_code))
        assert status_code == 0

        # 下载非过滤的文件
        log.warning('请求地址为{}'.format(self.allow_url))
        code = http_check.http_get(self.allow_url, flag=1)
        log.warning('下载非过滤的文件，请求返回的状态码为：{}'.format(code))
        assert code == 200

        # 下载过滤的文件
        log.warning('请求地址为{}'.format(self.deny_url))
        code = http_check.http_get(self.deny_url, flag=1)
        log.warning('下载过滤的文件，请求返回的状态码为：{}'.format(code))
        assert code == 0

        # 移除关键字过滤策略
        fun.send(rbmExc, tool.interface().keyword_interface(appid=tcp_appid, ruleid=self.tcp_ruleid), rbmDomain,
                 base_path)
        log.warning('检查内容审查策略是否移除成功')
        rule_list = self.tcp_ruleid.split(';')
        re = fun.wait_data(type=8, dut='gw')
        log.warning('预期不包含内容：{}'.format(rule_list))
        log.warning('查询keyword.json命令返回值：\n{}'.format(re))
        assert rule_list[0], rule_list[1] not in re

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='del_tcp_http'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        fdelres = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process', name='nginx进程')
        assert fdelres == 1

        # 检查代理策略是否下发成功
        fun.check_proxy_policy(type='tcp', flag=False)

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的ftp传输策略')
    def test_ftp_keyword(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        res = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process', name='前置机nginx进程')
        assert res == 1

        # 检查代理策略是否下发成功
        fun.check_proxy_policy(type='ftp')

        # 下发关键字过滤策略
        fun.send(rbmExc, tool.interface().keyword_interface(appid=ftp_appid, ruleid=self.ftp_ruleid,
                                                            pattern=f'{self.ftp_keyword1};{self.ftp_keyword2}'),
                 rbmDomain, base_path)
        log.warning('检查内容审查策略是否下发成功')
        rule_list = self.ftp_ruleid.split(';')
        re = fun.wait_data(type=8, dut='gw')
        log.warning('预期包含内容：{}'.format(rule_list))
        log.warning('查询keyword.json命令返回值：\n{}'.format(re))
        assert rule_list[0], rule_list[1] in re

        time.sleep(10)
        # 登录ftp服务器，上传命令被禁止
        fp = con_ftp.connect_ftp(proxy_ip, ftp_proxy_port, ftp_user, ftp_pass)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result = con_ftp.downFile(fp, self.case2_downremotePath, self.case2_downlocalPath)
        log.warning('上传命令被禁止的ftp传输策略，正常下载文件结果为:{}'.format(result))
        assert result == 1
        content = con_ftp.show_file_content(self.case2_downlocalPath)
        log.warning('被下载文件包含关键字内容{}，所以预期内容为[]'.format(self.ftp_keyword1))
        log.warning('查询下载的文件{} 内容为：{}'.format(self.case2_downlocalPath, content))
        assert content == []

        result = con_ftp.uploadFile(fp, self.case2_upremotePath, self.case2_uplocalPath)
        log.warning('上传命令被禁止的ftp传输策略，上传文件的结果为:{}'.format(result))
        assert result == 0

        # 移除关键字过滤策略
        fun.send(rbmExc, tool.interface().keyword_interface(appid=ftp_appid, ruleid=self.ftp_ruleid), rbmDomain,
                 base_path)
        log.warning('检查内容审查策略是否移除成功')
        rule_list = self.ftp_ruleid.split(';')
        re = fun.wait_data(type=8, dut='gw')
        log.warning('预期不包含内容：{}'.format(rule_list))
        log.warning('查询keyword.json命令返回值：\n{}'.format(re))
        assert rule_list[0], rule_list[1] not in re

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        fdelres = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process', name='前置机nginx进程')
        assert fdelres == 1

        # 检查代理策略是否移除成功
        fun.check_proxy_policy(type='ftp', flag=False)

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的邮件代理策略')
    def test_mail_keyword(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addsmtp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process', name='前置机nginx进程')
        assert res1 == 1
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addpop3'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process', name='前置机nginx进程')
        assert res2 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(type='smtp')
        fun.check_proxy_policy(type='pop3')

        # 下发关键字过滤策略
        fun.send(rbmExc, tool.interface().keyword_interface(appid=smtp_appid,
                                                            pattern=f'{self.juson_base64};{self.tech_base64};{self.smtp_keyword_base64}',
                                                            spattern=f'{self.juson_keyword};{self.tech_keyword};{self.smtp_keyword}'),
                 rbmDomain, base_path)
        fun.send(rbmExc, tool.interface().keyword_interface(appid=smtp_appid, ruleid=104,
                                                            pattern=f'{self.filename_keyword}'),
                 rbmDomain, base_path)
        fun.send(rbmExc, tool.interface().keyword_interface(appid=pop3_appid,
                                                            pattern=f'{self.pop3_keyword_base64}',
                                                            spattern=f'{self.pop3_keyword}'), rbmDomain, base_path)
        log.warning('检查内容审查策略是否下发成功')
        time.sleep(10)
        re = fun.wait_data(type=8, dut='gw')
        log.warning('查询keyword.json命令返回值：\n{}'.format(re))
        assert self.juson_base64 in re, '关键字：【' + self.juson_base64 + '】不存在文件keyword.json中'
        assert self.tech_base64 in re, '关键字：【' + self.tech_base64 + '】不存在文件keyword.json中'
        assert self.filename_keyword in re, '关键字：【' + self.filename_keyword + '】不存在文件keyword.json中'
        assert self.smtp_keyword_base64 in re, '关键字：【' + self.smtp_keyword_base64 + '】不存在文件keyword.json中'
        assert self.pop3_keyword_base64 in re, '关键字：【' + self.pop3_keyword_base64 + '】不存在文件keyword.json中'

        log.warning('---------- 开始发送邮件,邮件内容不包含关键字')
        result1 = send_smtp.post_email(mail_sender, mail_receivers, mail_cc, mail_bcc,
                                       proxy_ip, mail_port, mail_user, mail_pass,
                                       self.tech_file_path, self.file_tech, self.title, self.context, 0, 1)
        log.warning('邮件主题不包含关键字过滤的结果为:{}'.format(result1))
        assert result1 == 1

        log.warning('---------- 开始发送邮件，邮件主题包含关键字')
        result2 = send_smtp.post_email(mail_sender, mail_receivers, mail_cc, mail_bcc,
                                       proxy_ip, mail_port, mail_user, mail_pass,
                                       self.tech_file_path, self.file_tech, self.title_juson, self.context, 0, 0)
        log.warning('邮件主题包含关键字【{}】的结果为:{}'.format(self.juson_keyword, result2))
        assert result2 == 0

        log.warning('---------- 开始发送邮件，邮件正文包含关键字')
        result2 = send_smtp.post_email(mail_sender, mail_receivers, mail_cc, mail_bcc,
                                       proxy_ip, mail_port, mail_user, mail_pass,
                                       self.tech_file_path, self.file_tech, self.title, self.context_tech, 0, 0)
        log.warning('邮件正文包含关键字【{}】的结果为:{}'.format(self.tech_keyword, result2))
        assert result2 == 0

        log.warning('---------- 开始发送邮件，邮件附件内容包含关键字')
        result2 = send_smtp.post_email(mail_sender, mail_receivers, mail_cc, mail_bcc,
                                       proxy_ip, mail_port, mail_user, mail_pass,
                                       self.juson_file_path, self.file_juson, self.title, self.context, 0, 1)
        log.warning('邮件附件内容包含关键字【{}】的结果为:{}'.format(self.smtp_keyword, result2))
        assert result2 == 0

        log.warning('---------- 开始发送邮件，邮件附件文件名包含关键字')
        result2 = send_smtp.post_email(mail_sender, mail_receivers, mail_cc, mail_bcc,
                                       proxy_ip, mail_port, mail_user, mail_pass,
                                       self.juson_file_path, self.file_juson, self.title, self.context, 0, 1)
        log.warning('邮件附件文件名包含关键字【{}】的结果为:{}'.format(self.filename_keyword, result2))
        assert result2 == 0

        # 接收邮件
        log.warning('---------- 开始接收邮件，最新一封邮件的附件内容包含关键字')
        msg = recv_pop3.get_email(mail_receivers, mail_pass, proxy_ip, pop3_proxy_port)
        log.warning('接收邮件附件内容包含关键字【{}】的结果为:{}'.format(self.pop3_keyword, msg))
        assert msg == 0

        # 移除关键字过滤策略
        fun.send(rbmExc, tool.interface().keyword_interface(appid=smtp_appid, ruleid=4), rbmDomain, base_path)
        fun.send(rbmExc, tool.interface().keyword_interface(appid=pop3_appid, ruleid=1), rbmDomain, base_path)
        log.warning('检查内容审查策略是否移除成功')
        time.sleep(3)
        re = fun.wait_data(type=8, dut='gw')
        log.warning('查询keyword.json命令返回值：\n{}'.format(re))
        assert self.juson_base64 not in re, '关键字：【' + self.juson_base64 + '】存在文件keyword.json中'
        assert self.tech_base64 not in re, '关键字：【' + self.tech_base64 + '】存在文件keyword.json中'
        assert self.filename_keyword not in re, '关键字：【' + self.filename_keyword + '】存在文件keyword.json中'
        assert self.smtp_keyword_base64 not in re, '关键字：【' + self.smtp_keyword_base64 + '】存在文件keyword.json中'
        assert self.pop3_keyword_base64 not in re, '关键字：【' + self.pop3_keyword_base64 + '】存在文件keyword.json中'

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delsmtp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        fdelres1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process', name='前置机nginx进程')
        assert fdelres1 == 1
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delpop3'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        fdelres2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process', name='前置机nginx进程')
        assert fdelres2 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(type='smtp', flag=False)
        fun.check_proxy_policy(type='pop3', flag=False)

    def teardown_class(self):
        # 回收环境
        clr_env.data_check_teardown_met('mail', base_path)
        clr_env.data_check_teardown_met('ftp', base_path)
        clr_env.data_check_teardown_met('tcp_http', base_path)

        fun.rbm_close()
        fun.ssh_close('gw')
