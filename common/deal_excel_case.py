#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/12/1 20:01
import ftplib
import logging
# 将表格中读取格式过的内容进行再判断，并发送到设备端
import os
import sys
import time

from common import tool, baseinfo, fun
from common.baseinfo import ftp_appid, udp_appid
from data_check import http_check, con_ftp, send_smtp, recv_pop3

log = logging.getLogger(__name__)

base_path = os.path.dirname(os.path.abspath(__file__))  # 获取当前项目文件夹
base_path = base_path.replace('\\', '/')
version = baseinfo.version

gw_proxy_ip = baseinfo.gwClientIp
rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
iso_proxy_ip = baseinfo.BG8010FrontOpeIp
FrontDomain = baseinfo.BG8010FrontDomain

http_proxy_port = str(baseinfo.http_proxy_port)
ftp_proxy_port = baseinfo.ftp_proxy_port
smtp_proxy_port = baseinfo.smtp_proxy_port
pop3_proxy_port = baseinfo.pop3_proxy_port

http_ruleid = baseinfo.http_ruleid
ftp_ruleid = baseinfo.ftp_ruleid
smtp_ruleid = baseinfo.smtp_ruleid
pop3_ruleid = baseinfo.pop3_ruleid
smtp_appid = baseinfo.smtp_appid
pop3_appid = baseinfo.pop3_appid
tcp_appid = baseinfo.tcp_appid
tcp_ruleid = baseinfo.tcp_ruleid

ftp_ip = baseinfo.ftp_ip
ftp_dport = baseinfo.ftp_dport
ftp_user = baseinfo.ftp_user
ftp_pass = baseinfo.ftp_pass
ftp_downremotePath = baseinfo.ftp_downremotePath
ftp_downlocalPath = baseinfo.ftp_downlocalPath
ftp_upremotePath = baseinfo.ftp_upremotePath
ftp_uplocalPath = baseinfo.ftp_uplocalPath
ftp_uploadDirPath = baseinfo.ftp_uploadDirPath
ftp_delePath = baseinfo.ftp_delePath  # ftp删除的路径

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

mail_attach = baseinfo.mail_attach
title = '读表执行用例，业务有效性测试'
context = '测试内容-content'
file = '1.xls'
attach_file = mail_attach + file

t = time.localtime(time.time())


# http模块数据结构检查逻辑
def http_data_check(policy_num, policy_dict, dut):
    start_time = time.time()
    dutDomain = rbmDomain
    content_list, check_list, assert_list = policy_dict['content'], policy_dict['check'], policy_dict['assert']

    if policy_num == 'all':
        start_index = 0
        end_index = len(policy_dict['content'])
    else:
        start_index = int(policy_num) - 4
        end_index = int(policy_num) - 3

    if 'gw' == dut:
        dutDomain = rbmDomain
        proxy_ip = gw_proxy_ip
        addhttp = 'addhttp'
        delhttp = 'delhttp'
    elif 'Front' == dut:
        dutDomain = FrontDomain
        proxy_ip = iso_proxy_ip
        addhttp = 'addhttp_front'
        delhttp = 'delhttp_front'
    else:
        addhttp = None
        delhttp = None
        proxy_ip = None
        log.warning('无此种类型{}的设备，请检查后再试')

    log.warning('添加http业务')
    fun.send(rbmExc, tool.interface().setAccessconf(prototype=addhttp), dutDomain, base_path)
    # 清空数据结构检查策略，初始化环境
    fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), dutDomain, base_path)
    fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck', ruleid=http_ruleid + 1), dutDomain,
             base_path)

    time.sleep(5)
    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
    add_res1 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    assert add_res1 == 1

    fun.check_proxy_policy(dut=dut)
    log.warning('\n检查网页安全浏览策略是否清空')
    re = fun.wait_data(type=3, dut=dut, context=http_ruleid, flag=False)
    assert str(http_ruleid) not in re, '安全策略，环境初始化未成功'

    log.warning('发送一个基本请求，验证业务是否下发成功')
    http_url = 'http://' + proxy_ip + ':' + http_proxy_port
    status_code = http_check.http_get(http_url, flag=1)
    log.warning('普通请求【{}】的状态码为：{}'.format(http_url, status_code))
    assert status_code == 200, '普通请求验证失败'

    result_dict = {}
    result_policy_num = []
    result_check_method = []
    result_check_url = []
    result_assert = []
    result_code = []
    for i in range(start_index, end_index):
        log.warning(
            '================================================== HTTP 第{}行用例 =========================================================='.format(
                i + 4))

        # 在策略下发之前需要检查各种请求的文件是否存在
        read_flag = False
        ready_status = True
        file = None
        dir = None
        for check_param in check_list[i]:
            # 如果验证的url中包含.  则说明有关于文件的请求，需要环境初始化
            if '.' in check_param:
                read_flag = True
                file = check_param
            elif '/' in check_param:
                read_flag = True
                dir = check_param
        # 满足条件，需要检查服务端文件
        if read_flag:
            log.warning('该用例存在内容{}，需要环境初始化'.format(file if file is not None else dir))
            if file is not None:
                fun.ssh_httpServer.connect()
                # 判断文件是不是包含路径的
                if '/' in file:  # 包含路径
                    file_path = '/usr/share/nginx/html' + file.rsplit('/', 1)[0]
                    file_name = file.rsplit('/', 1)[1]
                else:
                    file_path = '/usr/share/nginx/html'
                    file_name = file
                log.warning('file_path: {}'.format(file_path))
                log.warning('file_name: {}'.format(file_name))
                # 需要提前查看文件是否存在
                search_file = fun.search(file_path, file_name.split('.')[1], 'httpServer')
                log.warning(
                    '检查服务端{}目录下所有以{}结尾的文件列表为：{}'.format(file_path, file_name.split('.')[1], search_file))
                if file_name in search_file:
                    log.warning('检查http服务端，文件{}已存在，不需要新建文件'.format(file_name))
                    ready_status = True
                else:
                    log.warning('检查http服务端，文件{}不存在，需要新建文件'.format(file_name))
                    ready_status = False

                if not ready_status:
                    # 直接新建服务端文件和文件夹
                    fun.ssh_httpServer.connect()
                    cmd = 'touch ' + file_path + '/' + file_name
                    fun.cmd(cmd=cmd, domain='httpServer')
                    log.warning('cmd:{}'.format(cmd))
                    # 新建后，再次检查是否存在，如果存在，则read_status = True，反之为False
                    search_file = fun.search(file_path, file_name.split('.')[1], 'httpServer')
                    log.warning('检查服务端{}目录下所有以{}结尾的文件列表为：{}'.format(file_path, file_name.split('.')[1], search_file))
                    if file_name in search_file:
                        log.warning('检查http服务端，文件{}已存在，初始化成功'.format(file_name))
                        ready_status = True
                    else:
                        log.warning('检查http服务端，文件{}不存在，初始化失败'.format(file_name))
                        ready_status = False
                # fun.ssh_httpServer.close()
            elif dir is not None:
                cmd = 'mkdir -p /usr/share/nginx/html' + dir
                fun.cmd(cmd=cmd, domain='httpServer')
                log.warning('cmd:{}'.format(cmd))
        else:
            log.warning('该用例不需要环境初始化')

        if ready_status:
            log.warning('\n检查策略内容的方式为：{}'.format(check_list[i]))
            # 下发数据结构检查策略
            for con in content_list[i]:
                log.warning('\n第{}行用例的策略内容为：{}'.format(i + 4, con))
                interface_msg = tool.interface().app_safe_policy(prototype='httpcheck', content_dict=con)
                # log.warning('第{}行用例的接口内容为：{}'.format(i + 4, interface_msg))
                fun.send(rbmExc, interface_msg, dutDomain, base_path)

            fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
            add_res2 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
            assert add_res2 == 1

            log.warning('\n检查网页应用安全策略是否下发成功')
            for con in content_list[i]:
                re = fun.wait_data(type=3, dut=dut, context=con['RuleId'])
                assert str(con['RuleId']) in re, '下发HTTP安全浏览策略,http.json文件不存在ruleid:{},文件内容为：\n{}'.format(con['RuleId'],
                                                                                                          re)

            if len(check_list[i]) == 2:
                http_url = 'http://' + proxy_ip + ':' + http_proxy_port
            elif len(check_list[i]) == 3:
                http_url = 'http://' + proxy_ip + ':' + http_proxy_port + check_list[i][2]
            elif len(check_list[i]) == 4:
                http_url = 'http://' + proxy_ip + ':' + http_proxy_port + check_list[i][2] + check_list[i][3]

            if check_list[i][0] == 'get':
                status_code = http_check.http_get(http_url, flag=1)
            elif check_list[i][0] == 'post':
                status_code = http_check.http_post(http_url, flag=1)
            elif check_list[i][0] == 'put':
                status_code = http_check.http_put(http_url, flag=1)
            elif check_list[i][0] == 'delete':
                status_code = http_check.http_delete(http_url, flag=1)
            else:
                log.warning('无{}方式的http请求，请检查用例表格再执行'.format(check_list[i][0]))
                sys.exit(0)
            if '放行' == assert_list[i]:
                if status_code != 200:
                    success_flag = 'fail'
                    result_policy_num.append(i)
                    result_check_method.append(check_list[i][0])
                    result_check_url.append(http_url)
                    result_assert.append(assert_list[i])
                    result_code.append(status_code)
                else:
                    success_flag = 'success'
            elif '阻断' == assert_list[i]:
                if status_code == 200:
                    success_flag = 'fail'
                    result_policy_num.append(i)
                    result_check_method.append(check_list[i][0])
                    result_check_url.append(http_url)
                    result_assert.append(assert_list[i])
                    result_code.append(status_code)
                else:
                    success_flag = 'success'
            else:
                log.warning('无此种【{}】预期结果，请检查后再运行'.format(assert_list[i]))
                sys.exit(0)
            log.warning(
                '\n请求url为【{}】预期结果为：{}，实际请求状态码为：{}，执行结果为：{}'.format(http_url, assert_list[i], status_code, success_flag))

            log.warning('清空网页访问策略')
            for con in content_list[i]:
                fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck', ruleid=con['RuleId']),
                         dutDomain, base_path)
                fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
                del_res2 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
                assert del_res2 == 1

                # log.warning('\n检查网页安全浏览策略是否清空')
                re = fun.wait_data(type=3, dut=dut, context=con['RuleId'], flag=False)
                # log.warning('预期不包含内容：{}'.format(con['RuleId']))
                # log.warning('查询http.json命令返回值：\n{}'.format(re))
                assert str(con['RuleId']) not in re, '清空HTTP安全浏览策略,http.json文件仍存在ruleid:{},文件内容为：\n{}'.format(
                    con['RuleId'], re)
        else:
            success_flag = 'fail'
            result_policy_num.append(i)
            result_check_method.append(check_list[i][0])
            result_check_url.append(http_url)
            result_assert.append(assert_list[i])
            result_code.append('初始化失败')

        log.warning('实时日志打印到文件 d_auto_test\\auto_test_dms\Logs\HTTP_datatime.txt')
        abs_path = os.path.dirname(os.path.abspath(__file__))
        parent_path = os.path.dirname(abs_path)  # 获得common所在的目录即common的父级目录，也就是auto_test_dms
        log_txt_path = parent_path + '\\Logs\\' + str(version) + '\\HTTP_case_result\\'
        log_filename = 'HTTP_' + time.strftime('%Y-%m-%d_%H-%M-%S', t)
        if not os.path.exists(log_txt_path):
            os.makedirs(log_txt_path)
        log_head = '\n--------------------------------------- 第{}行策略执行情况 --------------------------------------- '.format(
            i + 4)
        policy_content = '\n策略内容：{}'.format(content_list[i])
        policy_check = '\n请求方式【{}】所验证的URL为：{}'.format(check_list[i][0], http_url)
        policy_expected = '\n预期结果为：{}'.format(assert_list[i])
        policy_result = '\n实际执行返回码为：{}'.format(status_code)
        policy_re = '\n执行结果为：{}\n\n\n'.format(success_flag)
        with open(log_txt_path + log_filename + '.txt', 'a+') as log_file:
            log_file.write(log_head)
            log_file.write(policy_content)
            log_file.write(policy_check)
            log_file.write(policy_expected)
            log_file.write(policy_result)
            log_file.write(policy_re)
            log_file.flush()

    log.warning('\n移除业务，还原环境')
    fun.send(rbmExc, tool.interface().setAccessconf(prototype=delhttp), dutDomain, base_path)
    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
    del_res1 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    assert del_res1 == 1
    log.warning('\n检查代理策略是否移除成功')
    fun.check_proxy_policy(dut=dut, flag=False)

    # 执行结果处理
    result_dict['policy'] = result_policy_num
    result_dict['method'] = result_check_method
    result_dict['url'] = result_check_url
    result_dict['code'] = result_code

    if policy_num == 'all':
        all_policy_num = len(content_list)
    else:
        all_policy_num = 1
    end_time = time.time()
    log.warning('\nhttp模块的{}条用例的执行时间为：{}'.format(all_policy_num, round(end_time - start_time, 3)))
    return result_dict


# ftp模块数据结构检查逻辑
def ftp_data_check(policy_num, policy_dict, dut):
    dutDomain = rbmDomain
    param1 = None
    param2 = None

    if policy_num == 'all':
        start_index = 0
        end_index = len(policy_dict['content'])
    else:
        start_index = int(policy_num) - 4
        end_index = int(policy_num) - 3
    ready_status = True
    url_list = []
    content_list, check_list, assert_list = policy_dict['content'], policy_dict['check'], policy_dict['assert']
    if 'gw' == dut:
        dutDomain = rbmDomain
        proxy_ip = gw_proxy_ip
        addftp = 'addftp'
        delftp = 'delftp'
    elif 'Front' == dut:
        dutDomain = FrontDomain
        proxy_ip = iso_proxy_ip
        addftp = 'addftp_front'
        delftp = 'delftp_front'
    else:
        proxy_ip = None
        log.warning('无此种类型{}的设备，请检查后再试')

    log.warning('添加ftp业务')
    fun.send(rbmExc, tool.interface().setAccessconf(prototype=addftp), dutDomain, base_path)
    log.warning('清空数据结构检查策略，初始化环境')
    fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delftpcheck'), dutDomain, base_path)
    time.sleep(5)
    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
    add_res1 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    assert add_res1 == 1

    log.warning('正在检查FTP业务策略')
    fun.check_proxy_policy(dut=dut, type='ftp')
    log.warning('正在检查FTP安全浏览策略')
    re = fun.wait_data(type=4, dut=dut, context=ftp_ruleid, flag=False)
    # log.warning('预期不包含内容：{}'.format(ftp_ruleid))
    # log.warning('查询ftp.json命令返回值：\n{}'.format(re))
    assert str(ftp_ruleid) not in re, 'FTP安全策略环境初始化未成功，文件ftp.json中仍存在id：{}\nftp.json文件内容为：{}'.format(ftp_ruleid, re)

    log.warning('用户远程登录，验证业务是否下发成功')
    fp = con_ftp.connect_ftp(proxy_ip, ftp_proxy_port, ftp_user, ftp_pass)
    log.warning('欢迎语是：{}'.format(fp.getwelcome()))
    assert '220' in fp.getwelcome()
    fp.close()

    result_dict = {}
    result_policy_num = []
    result_policy_content = []
    result_check_user = []
    result_check_method = []
    result_check_file = []
    result_code = []
    for i in range(start_index, end_index):
        log.warning(
            '================================================== FTP 第{}行用例 =========================================================='.format(
                i + 4))
        # 在策略下发之前需要检查上传下载的文件是否存在
        # 如果长度为3，则属于对文件的操作
        if len(check_list[i]) == 3:
            action = check_list[i][1].split(':')[1]
            filename = check_list[i][2].split(':')[1]
            log.warning(
                '--------------------------该用例为{}文件：{}，需要环境初始化判断---------------------'.format(action, filename))
            # 下载、删除文件，需要判断服务器是否存在该文件，没有则提前上传
            if action == 'get' or action == 'delete':
                param1 = ftp_downremotePath + filename
                param2 = ftp_downlocalPath + filename
                path = ftp_downremotePath
                # 登录ftp,查询该路径下所有文件
                fp = con_ftp.connect_ftp(ftp_ip, ftp_dport, ftp_user, ftp_pass)
                try:
                    fp.cwd(path)
                except ftplib.error_perm:
                    log.warning('无法进入目录：{}'.format(path))
                # log.warning("当前所在位置:{}".format(fp.pwd()))  # 返回当前所在位置
                ftp_f_list = fp.nlst()  # 获取目录下文件、文件夹列表
                log.warning('该路径{}下包含以下内容：{}'.format(path, ftp_f_list))
                if filename not in ftp_f_list:
                    log.warning('不存在该文件，需要上传')
                    log.warning('上传文件为：{}，本地文件为：{}'.format(path + filename, ftp_uplocalPath + filename))
                    # 判断本地文件是否存在，不存在则需要上传
                    if not os.path.exists(param2):
                        log.warning('本地不存在该文件，需要新建')
                        open(param2, 'w')
                    time.sleep(1)
                    # 再次判断文件是否存在，不存在则表示初始化失败
                    if not os.path.exists(param2):
                        log.warning('本地新建失败，初始化失败')
                        ready_status = False
                    if ready_status:
                        result = con_ftp.uploadFile(fp, path + filename, ftp_uplocalPath + filename)
                        if result == 1:
                            log.warning('文件{}上传成功'.format(filename))
                        else:
                            log.warning('文件{}上传失败'.format(filename))
                        time.sleep(3)
                        # log.warning('再次检查文件夹中是否存在该文件')
                        fp.cwd(path)
                        ftp_f_list_after = fp.nlst()  # 获取目录下文件、文件夹列表
                        # log.warning('该路径{}下包含以下内容：{}'.format(path, ftp_f_list_after))
                        if filename not in ftp_f_list_after:
                            log.warning('再次检查，该文件夹下仍不存在该文件，初始化失败')
                            ready_status = False
                        else:
                            log.warning('再次检查，文件夹已存在该文件，初始化成功')
                else:
                    log.warning('文件已存在，不需要上传文件')
                fp.close()

            # 上传文件，需要判断本地是否存在该文件，没有则提前创建
            elif action == 'put':
                param1 = ftp_upremotePath + filename
                param2 = ftp_uplocalPath + filename
                # 如果本地不存在该文件则新建
                if not os.path.exists(param2):
                    log.warning('本地不存在该文件，需要新建')
                    open(param2, 'w')
                else:
                    log.warning('本地已存在该文件，不需要新建')
                time.sleep(1)
                # 再次判断文件是否存在，不存在则表示初始化失败
                if not os.path.exists(param2):
                    ready_status = False
            else:
                log.warning('暂不支持该种方式【{}】的ftp操作'.format(action))
                sys.exit(0)

        log.warning(
            '-------------------------- 环境初始化结束，开始执行用例 -----------------------------')
        # 下发数据结构检查策略
        for con in content_list[i]:
            interface_msg = tool.interface().app_safe_policy(prototype='ftpcheck', content_dict=con)
            log.warning('第{}条用例的策略内容为：{}'.format(i + 1, con))
            log.warning('\n检查策略内容的方式为：{}'.format(check_list[i]))
            # log.warning('第{}条用例的接口内容为：{}'.format(i + 1, interface_msg))
            fun.send(rbmExc, interface_msg, dutDomain, base_path)
            fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
            add_res2 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
            assert add_res2 == 1

            log.warning('\n检查FTP应用安全策略是否下发成功')
            re1 = fun.wait_data(type=4, dut=dut, context=ftp_ruleid)
            # log.warning('预期包含内容：{}'.format(ftp_ruleid))
            # log.warning('查询ftp.json命令返回值：\n{}'.format(re1))
            assert str(ftp_ruleid) in re1, '下发FTP安全浏览策略,ftp.json文件不存在ruleid:{},文件内容为：\n{}'.format(ftp_ruleid, re1)

        success_flag = 'fail'
        result = 0
        # 如果长度为1，则属于用户登录操作
        if len(check_list[i]) == 1:
            username = check_list[i][0].split(':')[1]
            log.warning('\n登录用户名为：{}，预期结果为{}'.format(username, assert_list[i]))
            log.warning('登录ftp服务器，策略预期结果为')
            fp = con_ftp.connect_ftp(proxy_ip, ftp_proxy_port, username, ftp_pass)
            if assert_list[i] == '放行':
                # log.warning('ftp用户{}欢迎语是：{}'.format(ftp_user, fp.getwelcome()))
                # assert '220' in fp.getwelcome()
                if fp != 0:
                    success_flag = 'success'
                    result = fp
                else:
                    success_flag = 'fail'
                    result = fp
            elif assert_list[i] == '阻断':
                if fp == 0:
                    success_flag = 'success'
                    result = fp
                else:
                    success_flag = 'fail'
                    result = fp
        # 如果长度为3，则属于对文件的操作
        elif len(check_list[i]) == 3:
            username = check_list[i][0].split(':')[1]
            action = check_list[i][1].split(':')[1]
            filename = check_list[i][2].split(':')[1]
            if ready_status:
                log.warning('环境初始化成功，开始 {}文件：{}'.format(action, filename))
                # 用户登录ftp服务器，如果登录失败，result也算0
                fp = con_ftp.connect_ftp(proxy_ip, ftp_proxy_port, username, ftp_pass)
                if fp == 0:
                    result = 0
                else:
                    result = 1
                # 登录成功再进行文件操作
                if result != 0:
                    # 下载文件
                    if action == 'get':
                        result = con_ftp.downFile(fp, param1, param2)
                    # 上传文件
                    elif action == 'put':
                        result = con_ftp.uploadFile(fp, param1, param2)
                    # 删除文件
                    elif action == 'delete':
                        result = con_ftp.deleallFile(fp, ftp_downremotePath, filename)
                log.warning('预期结果为:{}，实际结果为：{}'.format(assert_list[i], result))
                if assert_list[i] == '放行':
                    if result == 1:
                        success_flag = 'success'
                    elif result == 0:
                        success_flag = 'fail'
                elif assert_list[i] == '阻断':
                    if result == 1:
                        success_flag = 'fail'
                    elif result == 0:
                        success_flag = 'success'
                log.warning('第{}行用例，内容为{}\n执行结果为：{}\n\n'.format(i + 4, content_list[i], success_flag))
                url_list.append(check_list[i])
            else:
                log.warning('******************* 第{}个用例初始化失败，退出该用例测试 *******************\n\n'.format(i + 4))
                result = '初始化失败'
                success_flag = 'fail'

        if success_flag == 'fail':
            result_policy_num.append(i)
            result_policy_content.append(content_list[i])
            result_check_user.append(check_list[i][0])
            if len(check_list[i]) == 3:
                result_check_method.append(check_list[i][1])
                result_check_file.append(check_list[i][2])
            else:
                result_check_method.append('')
                result_check_file.append('')
            result_code.append(result)

        log.warning('清空FTP安全浏览策略，并检查')
        for con in content_list[i]:
            fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delftpcheck', ruleid=con['RuleId']),
                     dutDomain, base_path)
            fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
            del_res2 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
            assert del_res2 == 1

            re = fun.wait_data(type=4, dut=dut, context=con['RuleId'], flag=False)
            assert str(con['RuleId']) not in re, '清空FTP安全浏览策略,ftp.json文件仍存在ruleid:{},文件内容为：\n{}'.format(
                con['RuleId'], re)

        log.warning('实时日志打印到文件 d_auto_test\\auto_test_dms\Logs\FTP_datatime.txt')
        abs_path = os.path.dirname(os.path.abspath(__file__))
        parent_path = os.path.dirname(abs_path)  # 获得common所在的目录即common的父级目录，也就是auto_test_dms
        log_txt_path = parent_path + '\\Logs\\' + str(version) + '\\FTP_case_result\\'
        log_filename = 'FTP_' + time.strftime('%Y-%m-%d_%H-%M-%S', t)
        if not os.path.exists(log_txt_path):
            os.makedirs(log_txt_path)
        log_head = '\n--------------------------------------- 第{}行策略执行情况 --------------------------------------- '.format(
            i + 4)
        policy_content = '\n策略内容：{}'.format(content_list[i])
        policy_check = '\n验证方式为：{}'.format(check_list[i])
        policy_expected = '\n预期结果为：{}'.format(assert_list[i])
        policy_result = '\n实际执行返回码为：{}'.format(result)
        policy_re = '\n执行结果为：{}\n\n\n'.format(success_flag)
        with open(log_txt_path + log_filename + '.txt', 'a+') as log_file:
            log_file.write(log_head)
            log_file.write(policy_content)
            log_file.write(policy_check)
            log_file.write(policy_expected)
            log_file.write(policy_result)
            log_file.write(policy_re)
            log_file.flush()

    # 移除代理，还原环境
    fun.send(rbmExc, tool.interface().setAccessconf(prototype=delftp), dutDomain, base_path)
    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
    del_res1 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    assert del_res1 == 1
    # 检查代理策略是否移除成功
    fun.check_proxy_policy(dut=dut, type='ftp', flag=False)

    # 执行结果处理
    result_dict['policy'] = result_policy_num
    result_dict['content'] = result_policy_content
    result_dict['user'] = result_check_user
    result_dict['method'] = result_check_method
    result_dict['file'] = result_check_file
    result_dict['code'] = result_code

    # log.warning('=============================================================\n')
    # # log.warning(result_dict)
    # if policy_num == 'all':
    #     all_policy_num = len(content_list)
    # else:
    #     all_policy_num = 1
    #
    # if len(result_dict['policy']) == 0:
    #     log.warning('{}条用例全部成功，恭喜恭喜'.format(all_policy_num))
    # else:
    #     log.warning('共{}条用例，失败的用例有{}条，行号及内容为：'.format(all_policy_num, len(result_dict['policy'])))
    #     for i in range(len(result_dict['policy'])):
    #         # log.warning(result_dict['policy'][i] + 4)
    #         # log.warning(content_list[i])
    #         # log.warning(result_dict['method'][i])
    #         # log.warning(result_dict['url'][i])
    #         # log.warning(result_dict['code'][i])
    #         if result_dict['method'][i] == '':
    #             log.warning(
    #                 '用例表中第{}行策略内容为：{}\n{}\n请求状态码为：{}'.format(result_dict['policy'][i] + 4,
    #                                                          content_list[i],
    #                                                          result_dict['user'][i],
    #                                                          result_dict['code'][i]))
    #         else:
    #             log.warning(
    #                 '用例表中第{}行策略内容为：{}\n{}\n{}\n{}\n请求状态码为：{}'.format(result_dict['policy'][i] + 4,
    #                                                                  content_list[i],
    #                                                                  result_dict['user'][i],
    #                                                                  result_dict['method'][i],
    #                                                                  result_dict['file'][i],
    #                                                                  result_dict['code'][i]))
    #         log.warning('---------------------------------------------------------------------------------------------')

    # end_time = time.time()
    # log.warning('ftp模块的{}条用例的执行时间为：{}'.format(all_policy_num, round(end_time - start_time, 3)))

    return result_dict


# 邮件模块数据结构检查逻辑
def mail_data_check(policy_num, policy_dict, dut):
    dutDomain = rbmDomain
    # ready_status = False
    content_list, check_list, assert_list = policy_dict['content'], policy_dict['check'], policy_dict['assert']

    if policy_num == 'all':
        start_index = 0
        end_index = len(policy_dict['content'])
    else:
        start_index = int(policy_num) - 4
        end_index = int(policy_num) - 3

    if 'gw' == dut:
        dutDomain = rbmDomain
        proxy_ip = gw_proxy_ip
        add_smtp = 'addsmtp'
        add_pop3 = 'addpop3'
        del_smtp = 'delsmtp'
        del_pop3 = 'delpop3'
    elif 'Front' == dut:
        dutDomain = FrontDomain
        proxy_ip = iso_proxy_ip
        add_smtp = 'addsmtp_front'
        add_pop3 = 'addpop3_front'
        del_smtp = 'delsmtp_front'
        del_pop3 = 'delpop3_front'
    else:
        proxy_ip = None
        add_smtp = None
        add_pop3 = None
        del_smtp = None
        del_pop3 = None
        log.warning('无此种类型{}的设备，请检查后再试')

    log.warning('添加邮件业务')
    fun.send(rbmExc, tool.interface().setAccessconf(prototype=add_smtp), rbmDomain, base_path)
    fun.send(rbmExc, tool.interface().setAccessconf(prototype=add_pop3), rbmDomain, base_path)
    # 清空数据结构检查策略，初始化环境
    fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delmailcheck', appId=smtp_appid, ruleid=[104, 105]),
             dutDomain, base_path)
    fun.send(rbmExc,
             tool.interface().app_safe_policy(prototype='delmailcheck', appId=pop3_appid, ruleid=[104, 105, 106]),
             dutDomain, base_path)

    time.sleep(5)
    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
    add_res1 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    assert add_res1 == 1

    log.warning('\n检查邮件安全浏览策略是否清空')
    re = fun.wait_data(type=5, dut=dut, context=smtp_ruleid, flag=False)
    assert str(smtp_ruleid) not in re, '安全策略，环境初始化未成功，策略文件mail.json中仍存在ruleid：{}，文件内容如下：\n{}'.format(smtp_ruleid, re)
    re = fun.wait_data(type=5, dut=dut, context=pop3_ruleid, flag=False)
    assert str(pop3_ruleid) not in re, '安全策略，环境初始化未成功，策略文件mail.json中仍存在ruleid：{}，文件内容如下：\n{}'.format(pop3_ruleid, re)
    re = fun.wait_data(type=5, dut=dut, context=pop3_ruleid + 1, flag=False)
    assert str(pop3_ruleid + 1) not in re, '安全策略，环境初始化未成功，策略文件mail.json中仍存在ruleid：{}，文件内容如下：\n{}'.format(
        pop3_ruleid + 1, re)

    log.warning('\n检查邮件业务是否下发成功')
    fun.check_proxy_policy(dut=dut, type='smtp')
    fun.check_proxy_policy(dut=dut, type='pop3')
    log.warning('发送邮件，验证业务是否下发成功')
    # 发送邮件
    result1 = send_smtp.post_email(mail_sender, mail_receivers, mail_receivers, mail_receivers,
                                   proxy_ip, smtp_proxy_port, mail_user, mail_pass,
                                   attach_file, file, title, context, 0, 1)
    log.warning('地址{}发送邮件的结果为:{}'.format(mail_sender, result1))
    assert result1 == 1

    log.warning('接收邮件，验证业务是否下发成功')
    msg = recv_pop3.get_email(pop3_email, pop3_pwd, proxy_ip, pop3_proxy_port)
    mail_list = recv_pop3.print_info(msg)  # 解析
    assert title, context in mail_list

    result_dict = {}
    result_policy_num = []
    result_check_method = []
    result_code = []
    for i in range(start_index, end_index):
        log.warning(
            '================================================== MAIL 第{}行用例 =========================================================='.format(
                i + 4))
        filename = None
        # 收发邮件的结果，1为成功，0为失败
        mail_result = 0
        # 在策略下发之前需要检查smtp请求时，本地是否存在附件文件
        read_flag = False
        attachmentExt = None
        success_flag = False
        for check_param in check_list[i]:
            # 如果验证的url中包含.  则说明有关于文件的请求，需要环境初始化
            if 'AttachmentExt' in check_param:
                read_flag = True
                attachmentExt = check_param
        # 满足条件，需要检查服务端文件
        if read_flag:
            log.warning('该用例存在内容{}，需要环境初始化'.format(attachmentExt))
            if ';' in attachmentExt:
                filename = []
                ext = attachmentExt.split(':')[1]
                # 本地检查是否存在该后缀名的文件，文件名统一用1
                filename1 = mail_attach + '1.' + ext.split(';')[0]
                filename2 = mail_attach + '1.' + ext.split(';')[1]
                if not os.path.exists(filename1):
                    log.warning('本地不存在该文件，需要新建')
                    open(filename1, 'w')
                if not os.path.exists(filename2):
                    log.warning('本地不存在该文件，需要新建')
                    open(filename2, 'w')
                time.sleep(1)
                # 再次判断文件是否存在，不存在则表示初始化失败
                if not os.path.exists(filename1):
                    log.warning('本地文件{}新建失败，初始化失败'.format(filename1))
                    ready_status_1 = False
                else:
                    log.warning('本地文件{}新建成功，初始化成功'.format(filename1))
                    ready_status_1 = True
                if not os.path.exists(filename2):
                    log.warning('本地文件{}新建失败，初始化失败'.format(filename2))
                    ready_status_2 = False
                else:
                    log.warning('本地文件{}新建成功，初始化成功'.format(filename2))
                    ready_status_2 = True
                if ready_status_1 and ready_status_2:
                    ready_status = True
                    filename.append(filename1)
                    filename.append(filename2)
                else:
                    ready_status = True

            else:
                # 本地检查是否存在该后缀名的文件，文件名统一用1
                filename = mail_attach + '1.' + attachmentExt.split(':')[1]
                if not os.path.exists(filename):
                    log.warning('本地不存在该文件，需要新建')
                    open(filename, 'w')
                time.sleep(1)
                # 再次判断文件是否存在，不存在则表示初始化失败
                if not os.path.exists(filename):
                    log.warning('本地新建失败，初始化失败')
                    ready_status = False
                else:
                    log.warning('本地新建成功，初始化成功')
                    ready_status = True
        else:
            ready_status = True
            log.warning('该用例不需要环境初始化')

        if ready_status:
            log.warning('\n检查策略内容的方式为：{}'.format(check_list[i]))
            # 下发数据结构检查策略
            for con in content_list[i]:
                log.warning('\n第{}行用例的策略内容为：{}'.format(i + 4, con))
                appid = None
                if check_list[i][0] == 'SMTP':
                    appid = smtp_appid
                elif check_list[i][0] == 'POP3':
                    appid = pop3_appid
                interface_msg = tool.interface().app_safe_policy(prototype='mailcheck', content_dict=con, appId=appid)
                # log.warning('第{}条用例的接口内容为：{}'.format(i + 4, interface_msg))
                fun.send(rbmExc, interface_msg, dutDomain, base_path)

            fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
            add_res2 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
            assert add_res2 == 1

            log.warning('\n检查邮件应用安全策略是否下发成功')
            for con in content_list[i]:
                re = fun.wait_data(type=5, dut=dut, context=con['RuleId'])
                assert str(con['RuleId']) in re, '下发mail安全浏览策略,mail.json文件不存在ruleid:{},文件内容为：\n{}'.format(con['RuleId'],
                                                                                                          re)

            smtp_dict = {}
            pop3_ditc = {}
            recv_list = []
            cc_list = []
            # SMTP类型的安全策略
            if check_list[i][0] == 'SMTP':
                for check_param in check_list[i]:
                    if 'From' in check_param:
                        smtp_dict.update(From=check_param.split(':')[1])
                    if 'To' in check_param:
                        re_list = check_param.split(':')[1].split(';')
                        if len(re_list) == 1:
                            recv_list.append(re_list[0])
                        elif len(re_list) == 2:
                            recv_list.append(re_list[0])
                            recv_list.append(re_list[1])
                        else:
                            log.warning('暂未处理超过两人的邮件接收者')
                        smtp_dict.update(To=recv_list)
                    if '抄送' in check_param:
                        cc_list.append(check_param.split(':')[1])
                        smtp_dict.update(CC=cc_list)
                    if 'AttachmentExt' in check_param:
                        smtp_dict.update(AttachmentExt=check_param.split(':')[1])
                    if 'Subject' in check_param:
                        smtp_dict.update(Subject=check_param.split(':')[1])
                # 判断是单个附件还是两个附件，路径和文件名也是对应的字符串和列表
                if isinstance(filename, list):
                    file_name = []
                    file_name.append(filename[0].split('\\')[-1])
                    file_name.append(filename[1].split('\\')[-1])
                else:
                    file_name = filename.split('\\')[-1]
                mail_result = send_smtp.post_email(smtp_dict['From'] if 'From' in smtp_dict.keys() else '',  # 发送者
                                                   smtp_dict['To'] if 'To' in smtp_dict.keys() else '',  # 接收者
                                                   smtp_dict['CC'] if 'CC' in smtp_dict.keys() else '',  # 抄送人
                                                   smtp_dict['CC'] if 'CC' in smtp_dict.keys() else '',  # 暗送人
                                                   proxy_ip, smtp_proxy_port,  # 登录的ip和port
                                                   smtp_dict['From'] if 'From' in smtp_dict.keys() else '',  # 登录用户
                                                   mail_pass,  # 登录用户的密码
                                                   filename if read_flag else '',  # 附件的路径
                                                   file_name if read_flag else '',  # 附件的文件名
                                                   smtp_dict['Subject'] if 'Subject' in smtp_dict.keys() else '',
                                                   '读表执行用例的content', 0, 1 if read_flag else 0)
                log.warning('发送邮件的结果为:{}'.format(mail_result))
                if assert_list[i] == '放行':
                    if mail_result == 1:
                        success_flag = 'success'
                    else:
                        success_flag = 'fail'
                        result_policy_num.append(i)
                        result_check_method.append(check_list[i])
                        result_code.append('SMTP安全策略，预期放行，发送邮件失败')
                elif assert_list[i] == '阻断':
                    if mail_result == 1:
                        success_flag = 'fail'
                        result_policy_num.append(i)
                        result_check_method.append(check_list[i])
                        result_code.append('SMTP安全策略，预期阻断，发送邮件成功')
                    else:
                        success_flag = 'success'
                else:
                    log.warning('无此种【{}】预期结果，请检查后再运行'.format(assert_list[i]))

            # POP3类型的安全策略
            elif check_list[i][0] == 'POP3':
                for check_param in check_list[i]:
                    if 'From' in check_param:
                        pop3_ditc.update(From=check_param.split(':')[1])
                    if 'To' in check_param:
                        re_list = check_param.split(':')[1].split(';')
                        if len(re_list) == 1:
                            recv_list.append(re_list[0])
                        elif len(re_list) == 2:
                            recv_list.append(re_list[0])
                            recv_list.append(re_list[1])
                        else:
                            log.warning('暂未处理超过两人的邮件接收者')
                        pop3_ditc.update(To=recv_list)
                    if '抄送' in check_param:
                        cc_list.append(check_param.split(':')[1])
                        pop3_ditc.update(CC=cc_list)
                    if 'AttachmentExt' in check_param:
                        pop3_ditc.update(AttachmentExt=check_param.split(':')[1])
                    if 'Subject' in check_param:
                        pop3_ditc.update(Subject=check_param.split(':')[1])

                log.warning('开始发送邮件')
                # 判断是单个附件还是两个附件，路径和文件名也是对应的字符串和列表
                if isinstance(filename, list):
                    file_name = []
                    file_name.append(filename[0].split('\\')[-1])
                    file_name.append(filename[1].split('\\')[-1])
                else:
                    file_name = filename.split('\\')[-1]
                result1 = send_smtp.post_email(pop3_ditc['From'] if 'From' in pop3_ditc.keys() else '',  # 发送者
                                               pop3_ditc['To'] if 'To' in pop3_ditc.keys() else '',  # 接收者
                                               pop3_ditc['CC'] if 'CC' in pop3_ditc.keys() else '',  # 抄送人
                                               pop3_ditc['CC'] if 'CC' in pop3_ditc.keys() else '',  # 暗送人
                                               proxy_ip, smtp_proxy_port,  # 登录的ip和port
                                               pop3_ditc['From'] if 'From' in pop3_ditc.keys() else '',  # 登录用户
                                               mail_pass,  # 登录用户的密码
                                               filename if read_flag else '',  # 附件的路径
                                               file_name if read_flag else '',  # 附件的文件名
                                               pop3_ditc[
                                                   'Subject'] if 'Subject' in pop3_ditc.keys() else '读表执行pop3安全策略_{}'.format(
                                                   i + 4),
                                               '读表执行用例的content', 0, 1 if read_flag else 0)
                log.warning('发送邮件的结果为:{}'.format(result1))

                if result1 == 1:
                    time.sleep(10)
                    log.warning('\n开始接收邮件，预期结果为{}'.format(assert_list[i]))
                    # log.warning('收件人信息：\n{}\n{}\n{}\n{}'.format(pop3_ditc['From'][0] if 'From' in pop3_ditc.keys() else pop3_email, pop3_pwd,
                    #                               proxy_ip, pop3_proxy_port))
                    msg = recv_pop3.get_email(pop3_ditc['To'][0] if 'To' in pop3_ditc.keys() else pop3_email, pop3_pwd,
                                              proxy_ip, pop3_proxy_port)
                    if msg != 0:
                        mail_list = recv_pop3.print_info(msg)  # 解析
                        # log.warning('mail_list:\n{}'.format(mail_list))
                        if 'Subject' in pop3_ditc.keys():
                            if pop3_ditc['Subject'] in mail_list:
                                log.warning('邮箱最新邮件为刚发送的邮件')
                                mail_result = 1
                        elif '读表执行pop3安全策略_{}'.format(i + 4) in mail_list:
                            log.warning('邮箱最新邮件为刚发送的邮件')
                            mail_result = 1
                    else:
                        log.warning('邮件接收失败\n')
                        mail_result = 0

                    if assert_list[i] == '放行':
                        if mail_result == 1:
                            success_flag = 'success'
                        else:
                            success_flag = 'fail'
                            result_policy_num.append(i)
                            result_check_method.append(check_list[i])
                            result_code.append('pop3安全策略，预期放行，邮件接收失败')
                    elif assert_list[i] == '阻断':
                        if mail_result == 1:
                            success_flag = 'fail'
                            result_policy_num.append(i)
                            result_check_method.append(check_list[i])
                            result_code.append('pop3安全策略，预期阻断，邮件接收成功')
                        else:
                            success_flag = 'success'
                    else:
                        log.warning('无此种【{}】预期结果，请检查后再运行'.format(assert_list[i]))

                else:
                    log.warning('发送邮件失败，则不需要接收邮件，该用例执行失败')
                    success_flag = 'fail'
                    result_policy_num.append(i)
                    result_check_method.append(check_list[i])
                    result_code.append('pop3安全策略，发送邮件失败')

            log.warning('\n移除邮件安全策略策略')
            for con in content_list[i]:
                fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delmailcheck', ruleid=con['RuleId']),
                         dutDomain, base_path)
                fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
                del_res2 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
                assert del_res2 == 1

                re = fun.wait_data(type=3, dut=dut, context=con['RuleId'], flag=False)
                assert str(con['RuleId']) not in re, '清空mail安全浏览策略,mail.json文件仍存在ruleid:{},文件内容为：\n{}'.format(
                    con['RuleId'],
                    re)
        else:
            success_flag = 'fail'
            result_policy_num.append(i)
            result_check_method.append(check_list[i])
            result_code.append('初始化失败')

        log.warning('\n邮件安全策略执行结果为：{}'.format(success_flag))

        abs_path = os.path.dirname(os.path.abspath(__file__))
        parent_path = os.path.dirname(abs_path)  # 获得common所在的目录即common的父级目录，也就是auto_test_dms
        log_txt_path = parent_path + '\\Logs\\' + str(version) + '\\MAIL_case_result\\'
        log_filename = 'MAIL_' + time.strftime('%Y-%m-%d_%H-%M-%S', t)
        if not os.path.exists(log_txt_path):
            os.makedirs(log_txt_path)
        log_head = '\n--------------------------------------- 第{}行策略执行情况 --------------------------------------- '.format(
            i + 4)
        policy_content = '\n策略内容：{}'.format(content_list[i])
        policy_check = '\n检查策略内容的方式为：{}'.format(check_list[i])
        policy_expected = '\n预期结果为：{}'.format(assert_list[i])
        policy_result = '\n实际执行返回码为：{}'.format(mail_result)
        policy_re = '\n执行结果为：{}\n\n\n'.format(success_flag)
        with open(log_txt_path + log_filename + '.txt', 'a+') as log_file:
            log_file.write(log_head)
            log_file.write(policy_content)
            log_file.write(policy_check)
            log_file.write(policy_expected)
            log_file.write(policy_result)
            log_file.write(policy_re)
            log_file.flush()

    log.warning('\n移除业务，还原环境')
    fun.send(rbmExc, tool.interface().setAccessconf(prototype=del_smtp), rbmDomain, base_path)
    fun.send(rbmExc, tool.interface().setAccessconf(prototype=del_pop3), rbmDomain, base_path)
    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
    del_res1 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    assert del_res1 == 1
    log.warning('\n检查代理策略是否移除成功')
    fun.check_proxy_policy(type='smtp', dut=dut, flag=False)

    # 执行结果处理
    result_dict['policy'] = result_policy_num
    result_dict['method'] = result_check_method
    result_dict['code'] = result_code
    #
    # log.warning('=============================================================\n')
    # # log.warning(result_dict)
    # if policy_num == 'all':
    #     all_policy_num = len(content_list)
    # else:
    #     all_policy_num = 1
    #
    # if len(result_dict['policy']) == 0:
    #     log.warning('{}条用例全部成功，恭喜恭喜'.format(all_policy_num))
    # else:
    #     log.warning('共{}条用例，失败的用例有{}条，行号及内容为：\n'.format(all_policy_num, len(result_dict['policy'])))
    #     for i in range(len(result_dict['policy'])):
    #         # log.warning(result_dict['policy'][i] + 4)
    #         # log.warning(content_list[i])
    #         # log.warning(result_dict['method'][i])
    #         # log.warning(result_dict['url'][i])
    #         # log.warning(result_dict['code'][i])
    #         log.warning(
    #             '用例表中第{}行策略内容为：{}\n请求方式为：{}\n请求状态码为：{}'.format(result_dict['policy'][i] + 4,
    #                                                                      content_list[i],
    #                                                                      result_dict['method'][i],
    #                                                                      # result_dict['url'][i],
    #                                                                      result_dict['code'][i]))
    #         log.warning('---------------------------------------------------------------------------------------------')

    log.warning('实时日志打印到文件 d_auto_test\\auto_test_dms\Logs\MAIL_datatime.txt')
    # end_time = time.time()
    # log.warning('mail模块的{}条用例的执行时间为：{}'.format(all_policy_num, round(end_time - start_time, 3)))

    return result_dict


# 关键字过滤模块检查逻辑
def keyword_data_check(policy_num, policy_dict, dut):
    dutDomain = rbmDomain
    content_list, check_list, assert_list = policy_dict['content'], policy_dict['check'], policy_dict['assert']

    if policy_num == 'all':
        start_index = 0
        end_index = len(policy_dict['content'])
    else:
        start_index = int(policy_num) - 4
        end_index = int(policy_num) - 3

    deltcp = 'deltcp'
    deludp = 'deludp'
    if 'gw' == dut:
        dutDomain = rbmDomain
        proxy_ip = gw_proxy_ip
        addtcp = 'addtcp_proxy'
        addudp = 'addudp_proxy'
        addftp = 'addftp'
        delftp = 'delftp'
    elif 'Front' == dut:
        dutDomain = FrontDomain
        proxy_ip = iso_proxy_ip
        addtcp = 'addtcp_iso'
        addudp = 'addudp_iso'
        addftp = 'addftp_front'
        delftp = 'delftp_front'
    else:
        log.warning('无此种类型{}的设备，请检查后再试')

    # 清空关键字过滤策略，初始化环境
    fun.send(rbmExc, tool.interface().keyword_interface(appid=tcp_appid, ruleid=[tcp_ruleid, tcp_ruleid + 1]),
             dutDomain, base_path)
    fun.send(rbmExc, tool.interface().keyword_interface(appid=udp_appid, ruleid=[tcp_ruleid, tcp_ruleid + 1]),
             dutDomain, base_path)
    fun.send(rbmExc, tool.interface().keyword_interface(appid=ftp_appid, ruleid=[tcp_ruleid, tcp_ruleid + 1]),
             dutDomain, base_path)

    time.sleep(5)
    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
    add_res1 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    assert add_res1 == 1

    log.warning('\n检查关键字过滤策略是否清空')
    re = fun.wait_data(type=8, dut=dut)
    assert str(tcp_ruleid) not in re, '安全策略，环境初始化未成功，文件keyword.json中仍存在ruleid_{}，文件内容为：\n{}'.format(tcp_ruleid, re)
    re = fun.wait_data(type=8, dut=dut)
    assert str(tcp_ruleid + 1) not in re, '安全策略，环境初始化未成功，文件keyword.json中仍存在ruleid_{}，文件内容为：\n{}'.format(tcp_ruleid + 1,
                                                                                                        re)

    result_dict = {}
    result_policy_num = []
    result_check_method = []
    result_check_url = []
    result_assert = []
    result_code = []
    for i in range(start_index, end_index):
        log.warning(
            '================================================== 关键字过滤 第{}行用例 =========================================================='.format(
                i + 4))

        read_flag = False
        ready_status = False
        filepath = ''
        filename = 'keyword.txt'
        access_flag = 'fail'
        # ftp类型的文件传输，是从本地上传，所以在策略下发之前需要将传输的文件内容清空，重新写入测试内容
        for check_dir in check_list[i]:
            if 'para' in check_dir:
                check_content = check_dir.split(':')[1]
            if 'proto' in check_dir:
                proto = check_dir.split(':')[1]
            if 'filename' in check_dir:
                file = check_dir.split(':')[1]
                # 如果带-->，说明是指定大小的文件
                if '-->' in file:
                    filesize_filename = file.split('-->')[0]
                    filesize = file.split('-->')[1]
                    # 如果带/，说明文件中包含文件夹
                    if '/' in filesize_filename:
                        filepath = filesize_filename.rsplit('/', 1)[0][1:] + '\\'  # 去除第一个/
                        filename = filesize_filename.rsplit('/', 1)[1]
                    else:
                        filename = filesize_filename
                elif '.' not in file:
                    filename = file + '.txt'
                else:
                    filename = file
        log.warning('filepath:{}'.format(filepath))
        log.warning('filename:{}'.format(filename))
        log.warning('check_content:{}'.format(check_content))
        log.warning('proto:{}'.format(proto))
        if 'ftp' == proto:
            filepath = 'C:\\Users\\admin\\Desktop\\work\\' + filepath
            # log.warning('filepath2:{}'.format(filepath))
            localfile = filepath + filename
            log.warning('该用例文件为：{}'.format(localfile))
            # 如果是指定大小的文件，容量又不为G，
            if filename[0] == '1':
                # log.warning('{}为指定容量的文件'.format(localfile))
                if not os.path.exists(localfile):
                    # 手动创建命令：fsutil file createnew 100k.txt 102400
                    log.warning('文件 {} 不存在，需提前手动创建，初始化失败'.format(localfile))
                    read_flag = False
                else:
                    read_flag = True
                # 容量不为G的，则检查内容后再决定是否追加内容
                if 'G' not in filename:
                    # 查询文件内容
                    file_content = con_ftp.show_file_content(localfile)
                    # log.warning('文件内容为：{}'.format(file_content))
                    if check_content not in file_content:
                        # 追加式写入内容
                        with open(localfile, 'a') as f:
                            print(check_content, file=f)
                else:
                    log.warning('文件为{}，直接追加内容来完成初始化'.format(filename))
            # 剩下的就是没有指定大小的文件，文件名默认 keyword.txt
            else:
                read_flag = True
                # 判断文件是否存在
                if not os.path.exists(localfile):
                    # 不存在则新建该文件
                    open(localfile, 'w')
                # 清空该文件内容
                with open(localfile, 'w') as f1:
                    f1.seek(0)
                    f1.truncate()
                # 覆盖式写入内容
                with open(localfile, 'w') as f:
                    print(check_content, file=f)
            if read_flag:
                log.warning('环境初始化后，再次检查该文件中是否存在该内容')
                file_content = con_ftp.show_file_content(localfile)
                file_content_str = ''.join(file_content)
                # log.warning('文件内容：{}'.format(file_content))
                # log.warning('文件str：{}'.format(file_content_str))
                # log.warning('检查内容：{}'.format(check_content))
                if check_content in file_content_str:
                    ready_status = True
                    log.warning('该文件内存在该内容，初始化成功')
                else:
                    ready_status = False
                    log.warning('该文件内仍不存在该内容，初始化失败')
            else:
                ready_status = False
        elif 'tcp' == proto or 'udp' == proto:
            # 先判断客户端/opt/pkt 下是否存在该文件
            fun.ssh_BG8010Client.connect()
            files = fun.cmd('ls /opt/pkt', 'BG8010Client')
            if filename in files:
                read_flag = True
            else:
                read_flag = False

            # 如果不存在，则需要新建，并且写入特定内容
            if not read_flag:
                create_file_cmd = None
                if filename.split('.')[0] == '100k':
                    create_file_cmd = 'cd /opt/pkt && dd if=/dev/zero of=' + filename + ' bs=1K count=100'
                elif filename.split('.')[0] == '1M':
                    create_file_cmd = 'cd /opt/pkt && dd if=/dev/zero of=' + filename + ' bs=1M count=1'
                elif filename.split('.')[0] == '10M':
                    create_file_cmd = 'cd /opt/pkt && dd if=/dev/zero of=' + filename + ' bs=1M count=10'
                elif filename.split('.')[0] == '100M':
                    create_file_cmd = 'cd /opt/pkt && dd if=/dev/zero of=' + filename + ' bs=1M count=100'
                elif 'G' in filename.split('.')[0]:
                    ready_status = False
                    read_flag = False
                    log.warning('文件{}过大，需要手动创建，初始化失败'.format(filename))
                else:
                    create_file_cmd = 'touch /opt/pkt/keyword.txt'
                if create_file_cmd is not None:
                    log.warning('文件{}不存在，正在创建该文件'.format(filename))
                    log.warning('create_file_cmd：{}'.format(create_file_cmd))
                    fun.cmd(create_file_cmd, 'BG8010Client')
                    read_flag = True
            # 文件存在，且不是G容量的文件
            elif read_flag and 'G' not in filename.split('.')[0]:
                show_content_cmd = 'cat /opt/pkt/' + filename
                log.warning('show_content_cmd:{}'.format(show_content_cmd))
                c = fun.cmd(show_content_cmd, 'BG8010Client')
                if check_content in c:
                    log.warning('文件{}中包含检查内容{}，不需要初始化'.format(filename, check_content))
                    ready_status = True
                else:
                    echo_content_cmd = "echo -e '" + check_content + "' > /opt/pkt/" + filename + ""
                    log.warning('echo_content_cmd:{}'.format(echo_content_cmd))
                    fun.cmd(echo_content_cmd, 'BG8010Client')
                    # 写入后再次检查文件中是否包含检查内容
                    c = fun.cmd(show_content_cmd, 'BG8010Client')
                    if check_content in c:
                        log.warning('文件【{}】中已包含检查内容【{}】，初始化成功'.format(filename, check_content))
                        ready_status = True
                    else:
                        log.warning('echo追加内容【{}】后，文件【{}】内仍然查询不到该内容，初始化失败'.format(check_content, filename))
                        ready_status = False
            elif read_flag and 'G' in filename.split('.')[0]:
                log.warning('文件【{}】过大，查询不便，直接插入内容，完成初始化'.format(filename))
                echo_content_cmd = "echo -e '" + check_content + "' > /opt/pkt/" + filename + ""
                log.warning('echo_content_cmd:【{}】'.format(echo_content_cmd))
                fun.cmd(echo_content_cmd, 'BG8010Client')
                ready_status = True
            else:
                log.warning('------------------------------------------------文件【{}】需要检查，再进行初始化'.format(filename))
            fun.ssh_BG8010Client.close()
        if ready_status:
            log.warning('初始化完成，准备下发策略')
            log.warning('proto:{}'.format(proto))
            log.warning('check_content:{}'.format(check_content))
            # 根据不同协议，下发不同的业务
            # 协议类型为ftp
            if proto == 'ftp':
                appid = ftp_appid
                # 下发ftp的业务
                log.warning('\n添加ftp业务')
                fun.send(rbmExc, tool.interface().setAccessconf(appId=appid, prototype=addftp), dutDomain, base_path)
                log.warning('检查业务是否下发成功')
                proxy_file = '/etc/jsac/other_proxy/' + str(ftp_appid) + '_' + str(ftp_proxy_port) + '_ftp.stream'
                check_proxy_file_cmd = 'cat ' + proxy_file
                log.warning('dut:{}'.format(dut))
                proxy_file_content = fun.cmd(check_proxy_file_cmd, dut)
                proxy_content = str(proxy_ip) + ':' + str(ftp_proxy_port)
                if proxy_content not in proxy_file_content:
                    access_flag = 'fail_代理文件检查失败'
                    log.warning(
                        '代理文件{}中没有指定内容：{},文件内容如下：\n{}'.format(proxy_file, proxy_content, proxy_file_content))
                else:
                    netstat = fun.cmd('netstat -ntlp', dut)
                    if proxy_content not in netstat:
                        access_flag = 'fail_端口检查失败'
                        log.warning('端口检查失败，检查内容为：{}，实际返检查结果为：\n{}'.format(proxy_content, netstat))
                    else:
                        log.warning('用户远程登录，验证业务是否下发成功')
                        fp = con_ftp.connect_ftp(proxy_ip, ftp_proxy_port, ftp_user, ftp_pass)
                        if fp != 0:
                            log.warning('欢迎语是：{}'.format(fp.getwelcome()))
                            if '220' not in fp.getwelcome():
                                access_flag = 'fail_业务验证请求失败'
                            else:
                                access_flag = 'success'
                        else:
                            access_flag = 'fail_业务验证请求失败'
            # 协议类型为tcp和udp
            elif proto == 'tcp' or proto == 'udp':
                if proto == 'tcp':
                    netstat_cmd = 'netstat -ntlp'
                    appid = tcp_appid
                    proxy_port = 2288
                    log.warning('\n添加tcp业务')
                    fun.send(rbmExc,
                             tool.interface().setAccessconf(appId=appid, prototype=addtcp, Mode=2, server_port=2288,
                                                            proxy_port=proxy_port), dutDomain, base_path)
                else:
                    netstat_cmd = 'netstat -nulp'
                    appid = udp_appid
                    proxy_port = 2289
                    # 下发ftp的业务
                    log.warning('\n添加udp业务')
                    fun.send(rbmExc,
                             tool.interface().setAccessconf(appId=appid, prototype=addudp, Mode=2, server_port=2289,
                                                            proxy_port=2289), dutDomain, base_path)
                time.sleep(3)
                log.warning('检查业务是否下发成功')
                proxy_file = '/etc/jsac/other_proxy/' + str(appid) + '_' + str(proxy_port) + '_.stream'
                check_proxy_file_cmd = 'cat ' + proxy_file
                proxy_file_content = fun.cmd(check_proxy_file_cmd, dut)
                proxy_content = str(proxy_ip) + ':' + str(proxy_port)
                if proxy_content not in proxy_file_content:
                    access_flag = 'fail_代理文件检查失败'
                    log.warning(
                        '代理文件{}中没有指定内容：{},文件内容如下：\n{}'.format(proxy_file, proxy_content, proxy_file_content))
                else:
                    netstat = fun.cmd(netstat_cmd, dut)
                    if proxy_content not in netstat:
                        access_flag = 'fail_端口检查失败'
                        log.warning('端口检查失败，检查内容为：{}，实际返检查结果为：\n{}'.format(proxy_content, netstat))
                    else:
                        access_flag = 'success'
            else:
                log.warning('暂未支持解析此种协议【{}】的关键字过滤'.format(proto))
            log.warning('appid:{}'.format(appid))

            if access_flag == 'success':
                # 下发关键字过滤策略
                for con in content_list[i]:
                    # 上传本地文件到ftp服务，用的是ftp的代理业务
                    log.warning('\n第{}行用例的策略内容为：{}'.format(i + 4, con))
                    interface_msg = tool.interface().keyword_interface(appid=appid, content_dict=con)
                    # log.warning('第【{}】条用例的接口内容为：{}'.format(i + 1, interface_msg))
                    fun.send(rbmExc, interface_msg, dutDomain, base_path)

                fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
                add_res2 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
                assert add_res2 == 1

                log.warning('\n检查关键字过滤策略是否下发成功')
                for con in content_list[i]:
                    re = fun.wait_data(type=8, dut=dut, context=con['RuleId'])
                    assert str(con['RuleId']) in re, '下发关键字过滤策略,keyword.json文件不存在ruleid:【{}】,文件内容为：\n{}'.format(
                        con['RuleId'], re)

                log.warning('\n开始验证策略是否生效')
                if proto == 'ftp':
                    result = con_ftp.uploadFile(fp, ftp_upremotePath + filename, ftp_uplocalPath + filename)
                    if result == 1:
                        log.warning('文件【{}】上传成功'.format(filename))
                    else:
                        log.warning('文件【{}】上传失败'.format(filename))
                elif proto == 'tcp' or proto == 'udp':
                    if proto == 'tcp':
                        server_py = 'tcp_server_file.py'
                        client_py = 'tcp_client_file.py'
                    else:
                        server_py = 'udp_server_file.py'
                        client_py = 'udp_client_file.py'
                    fun.ssh_BG8010Client.connect()
                    fun.ssh_BG8010Server.connect()
                    log.warning('1、删除服务端文件')
                    del_cmd = 'rm -rf /opt/pkt/' + filename
                    log.warning('del_cmd: {}'.format(del_cmd))
                    fun.cmd(del_cmd, 'BG8010Server')
                    log.warning('2、服务端监听等待')
                    time.sleep(1)
                    recv_cmd = 'cd /opt/pkt && python3 ' + server_py
                    log.warning('recv_cmd: {}'.format(recv_cmd))
                    fun.cmd(recv_cmd, 'BG8010Server', thread=1)
                    time.sleep(2)
                    log.warning('3、客户端发送文件')
                    send_cmd = 'cd /opt/pkt && python3 ' + client_py + ' --filename=' + filename
                    log.warning('send_cmd: {}'.format(send_cmd))
                    fun.cmd(send_cmd, 'BG8010Client')
                    time.sleep(2)
                    log.warning('4、检查服务端是否存在该文件')
                    log.warning('check_cmd: {}'.format('ls /opt/pkt'))
                    file_list = fun.cmd('ls /opt/pkt', 'BG8010Server')
                    if filename not in file_list:
                        log.warning('5、发送失败，服务端并没有该文件')
                        result = 0
                    else:
                        log.warning('5、发送成功再检查内容')
                        context = fun.cmd('cat /opt/pkt/' + filename, 'BG8010Server')
                        log.warning('文件内容为：{}'.format(context))
                        log.warning('验证内容为：{}'.format(check_content))
                        if check_content in context:
                            result = 1
                        else:
                            result = 0
                    fun.ssh_BG8010Client.close()
                    fun.ssh_BG8010Server.close()

                log.warning('result:{}'.format(result))

                success_flag = 'success'
                if '放行' == assert_list[i]:
                    if result != 1:
                        success_flag = 'fail'
                        result_policy_num.append(i)
                        result_check_method.append(proto)
                        result_assert.append(assert_list[i])
                        result_code.append(result)
                    else:
                        success_flag = 'success'
                elif '阻断' == assert_list[i]:
                    if result == 1:
                        success_flag = 'fail'
                        result_policy_num.append(i)
                        result_check_method.append(proto)
                        result_assert.append(assert_list[i])
                        result_code.append(result)
                    else:
                        success_flag = 'success'
                else:
                    log.warning('无此种【{}】预期结果，请检查后再运行'.format(assert_list[i]))
                    sys.exit(0)
                log.warning(
                    '\n请求方式为【{}】预期结果为：{}，实际请求状态码为：{}，执行结果为：{}'.format(check_list[i], assert_list[i], result,
                                                                      success_flag))

                log.warning('清空关键字过滤策略')
                for con in content_list[i]:
                    log.warning('appid: {}'.format(appid))
                    log.warning('ruleid: {}'.format(con['RuleId']))
                    fun.send(rbmExc, tool.interface().keyword_interface(appid=appid, ruleid=con['RuleId']),
                             dutDomain, base_path)
                    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
                    del_res2 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
                    assert del_res2 == 1

                    # log.warning('\n检查网页安全浏览策略是否清空')
                    re = fun.wait_data(type=8, dut=dut, context=con['RuleId'], flag=False)
                    assert str(con['RuleId']) not in re, '清空关键字过滤策略,keyword.json文件仍存在ruleid:【{}】,文件内容为：\n{}'.format(
                        con['RuleId'], re)

            else:
                success_flag = 'fail'
                result_policy_num.append(i)
                result_check_method.append(proto)
                result_assert.append(assert_list[i])
                result_code.append(access_flag.split('_')[1])
                result = access_flag.split('_')[1]

            # 根据不同协议，移除不同的业务
            # 协议类型为ftp
            if proto == 'ftp':
                # 移除ftp的业务
                log.warning('移除ftp业务')
                fun.send(rbmExc, tool.interface().setAccessconf(appId=appid, prototype=delftp), dutDomain,
                         base_path)
            # 协议类型为tcp
            elif proto == 'tcp':
                # 移除tcp的业务
                log.warning('移除tcp业务')
                fun.send(rbmExc, tool.interface().setAccessconf(appId=appid, prototype=deltcp), dutDomain,
                         base_path)
            # 协议类型为udp
            elif proto == 'udp':
                # 移除udp的业务
                log.warning('移除udp业务')
                fun.send(rbmExc, tool.interface().setAccessconf(appId=appid, prototype=deludp), dutDomain,
                         base_path)
            else:
                log.warning('暂未支持解析此种协议【{}】的关键字过滤'.format(proto))
        else:
            success_flag = 'fail'
            result_policy_num.append(i)
            result_check_method.append(proto)
            result_assert.append(assert_list[i])
            result_code.append('初始化失败')
            result = '初始化失败'

        log.warning('实时日志打印到文件 d_auto_test\\auto_test_dms\Logs\Keyword_datatime.txt')
        abs_path = os.path.dirname(os.path.abspath(__file__))
        parent_path = os.path.dirname(abs_path)  # 获得common所在的目录即common的父级目录，也就是auto_test_dms
        log_txt_path = parent_path + '\\Logs\\' + str(version) + '\\Keyword_case_result\\'
        log_filename = 'Keyword_' + time.strftime('%Y-%m-%d_%H-%M-%S', t)
        if not os.path.exists(log_txt_path):
            os.makedirs(log_txt_path)
        log_head = '\n--------------------------------------- 第{}行策略执行情况 --------------------------------------- '.format(
            i + 4)
        policy_content = '\n策略内容：{}'.format(content_list[i])
        policy_check = '\n请求方式【{}】'.format(proto)
        policy_expected = '\n预期结果为：{}'.format(assert_list[i])
        policy_result = '\n实际执行返回码为：{}'.format(result)
        policy_re = '\n执行结果为：{}\n\n\n'.format(success_flag)
        with open(log_txt_path + log_filename + '.txt', 'a+') as log_file:
            log_file.write(log_head)
            log_file.write(policy_content)
            log_file.write(policy_check)
            log_file.write(policy_expected)
            log_file.write(policy_result)
            log_file.write(policy_re)
            log_file.flush()

    # 执行结果处理
    result_dict['policy'] = result_policy_num
    result_dict['method'] = result_check_method
    result_dict['url'] = result_check_url
    result_dict['code'] = result_code

    return result_dict


# 定制应用模块处理表格用例逻辑
def app_data_check(policy_num, policy_dict, dut):
    dutDomain = rbmDomain
    content_list, check_list, assert_list = policy_dict['content'], policy_dict['check'], policy_dict['assert']

    if policy_num == 'all':
        start_index = 0
        end_index = len(policy_dict['content'])
    else:
        start_index = int(policy_num) - 4
        end_index = int(policy_num) - 3

    del_tcp = 'deltcp'
    if 'gw' == dut:
        dutDomain = rbmDomain
        proxy_ip = gw_proxy_ip
        add_tcp = 'addtcp_proxy'
    elif 'Front' == dut:
        dutDomain = FrontDomain
        proxy_ip = iso_proxy_ip
        add_tcp = 'addtcp_iso'
    else:
        proxy_ip = None
        add_tcp = None
        log.warning('无此种类型【{}】的设备，请检查后再试')

    log.warning('添加tcp业务')
    fun.send(rbmExc, tool.interface().setAccessconf(prototype=add_tcp, Mode=2, server_port=22), dutDomain,
             base_path)
    log.warning('清空定制应用策略，初始化环境')
    fun.send(rbmExc, tool.interface().UDA_app_interface(ruleid=tcp_ruleid), dutDomain, base_path)
    fun.send(rbmExc, tool.interface().UDA_app_interface(ruleid=tcp_ruleid + 1), dutDomain,
             base_path)

    time.sleep(5)
    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
    add_res1 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    assert add_res1 == 1

    fun.check_proxy_policy(type='tcp', dut=dut)
    log.warning('\n检查定制应用策略是否清空')
    re = fun.wait_data(type=9, dut=dut, context=tcp_ruleid, flag=False)
    assert str(tcp_ruleid) not in re, '定制应用策略，环境初始化未成功，custom_app.json文件中仍存在ruleid_{}'.format(tcp_ruleid)
    re = fun.wait_data(type=9, dut=dut, context=tcp_ruleid + 1, flag=False)
    assert str(tcp_ruleid + 1) not in re, '定制应用策略，环境初始化未成功，custom_app.json文件中仍存在ruleid_{}'.format(tcp_ruleid + 1)

    log.warning('\n发送一个基本请求，验证业务是否下发成功')
    # 目的端口为22的验证方式需要修改，下面这个是目的端口为80的验证方式
    # http_url = 'http://' + proxy_ip + ':' + http_proxy_port
    # status_code = http_check.http_get(http_url, flag=1)
    # log.warning('普通请求【{}】的状态码为：{}'.format(http_url, status_code))
    # assert status_code == 200, '普通请求验证失败'

    result_dict = {}
    result_policy_num = []
    result_check_method = []
    result_check_url = []
    result_assert = []
    result_code = []
    for i in range(start_index, end_index):
        log.warning(
            '================================================== 定制应用 第{}行用例 =========================================================='.format(
                i + 4))

        # 在策略下发之前需要检查各种请求的文件是否存在
        read_flag = False
        ready_status = True
        file = None
        for check_param in check_list[i]:
            # 如果验证的url中包含.  则说明有关于文件的请求，需要环境初始化
            if '.' in check_param:
                read_flag = True
                file = check_param.split('/')[-1]
        # 满足条件，需要检查服务端文件
        if read_flag:
            log.warning('该用例存在内容【{}】，需要环境初始化'.format(file))
            # 直接新建服务端文件和文件夹
            if file is not None:
                fun.ssh_httpServer.connect()
                file_size = file.split('.')[0]
                file_type = file.split('.')[1]
                if '10G' in file or '1G' in file or '100M' in file:
                    if '10G' in file:
                        log.warning('该文件为{}容量的文件，需要手动初始化'.format(file_size))
                        # fun.cmd('cd /opt/pkt && dd if=/dev/zero of=10G.pdf bs=1M count=10240', 'httpServer')
                    elif '1G' in file:
                        fun.cmd('cd /opt/pkt && dd if=/dev/zero of=1G.pdf bs=1M count=1024', 'httpServer')
                    elif '100M' in file:
                        fun.cmd('cd /opt/pkt && dd if=/dev/zero of=100M.pdf bs=1M count=100', 'httpServer')
                else:
                    cmd = 'touch /usr/share/nginx/html/' + file
                    log.warning('cmd:{}'.format(cmd))
                    fun.cmd(cmd=cmd, domain='httpServer')
                    time.sleep(20)
                # 检查服务端文件是否创建成功
                search_file = fun.search('/usr/share/nginx/html', file_type, 'httpServer')
                # log.warning('检查服务端/usr/share/nginx/html目录下所有以{}结尾的文件列表为：{}'.format(file_type, search_file))
                if file in search_file:
                    log.warning('检查http服务端，文件【{}】已存在，初始化成功'.format(file))
                    ready_status = True
                else:
                    log.warning('检查http服务端，文件【{}】不存在，初始化失败'.format(file))
                    ready_status = False
                # fun.ssh_httpServer.close()

        else:
            log.warning('该用例不需要环境初始化')
        if ready_status:
            log.warning('\n检查策略内容的方式为：{}'.format(check_list[i]))
            # 下发数据结构检查策略
            for con in content_list[i]:
                log.warning('\n第{}行用例的策略内容为：{}'.format(i + 4, con))
                interface_msg = tool.interface().UDA_app_interface(content_dict=con)
                # log.warning('第{}条用例的接口内容为：{}'.format(i + 1, interface_msg))
                fun.send(rbmExc, interface_msg, dutDomain, base_path)

            fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
            add_res2 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
            assert add_res2 == 1

            log.warning('\n检查定制应用策略是否下发成功')
            for con in content_list[i]:
                re = fun.wait_data(type=9, dut=dut, context=con['RuleId'])
                assert str(con['RuleId']) in re, '下发定制应用策略,custom_app.json文件不存在ruleid:{},文件内容为：\n{}'.format(
                    con['RuleId'], re)
            http_url = None
            if check_list[i][0] == 'get':
                http_url = 'http://' + proxy_ip + ':' + http_proxy_port
                status_code = http_check.http_get(http_url, flag=1)
                log.warning('请求url为【{}】预期结果为：{}，实际请求状态码为：{}'.format(http_url, assert_list[i], status_code))
            elif check_list[i][0] == 'wget':
                fun.ssh_BG8010Client.connect()
                http_url = 'wget ' + check_list[i][1].replace('代理ip', proxy_ip).replace('代理port', http_proxy_port)
                status_code = fun.cmd(http_url, 'BG8010Client')
                log.warning('请求url为【{}】预期结果为：{}，实际请求状态码为：{}'.format(http_url, assert_list[i], status_code))
                fun.ssh_BG8010Client.close()
            elif '上传' in check_list[i][0]:
                step_1 = check_list[i][0].split('：')[1].replace('代理ip', proxy_ip).replace('代理port',
                                                                                          http_proxy_port).replace(
                    '/local_file_path/local_file_name', '/opt/pkt/1.txt').replace('/remote_file_path',
                                                                                  '/opt/pkt')
                log.warning('step_1_上传：{}'.format(step_1))
                http_url = step_1
                step_2 = check_list[i][1].split('：')[1].replace('代理ip', proxy_ip).replace('代理port',
                                                                                          http_proxy_port).replace(
                    '/local_file_path', '/opt/pkt').replace('/remote_file_path/remote_file_name', '/opt/pkt/1.txt')
                log.warning('step_2_下载：{}'.format(step_2))
                step_3 = check_list[i][2].split('：')[1].replace('代理ip', proxy_ip).replace('代理port', http_proxy_port)
                log.warning('step_3_ssh：{}'.format(step_3))

                fun.ssh_BG8010Client.connect()
                fun.ssh_BG8010Server.connect()
                status_code1 = fun.cmd(step_1, 'BG8010Client')
                log.warning('步骤一:{}的命令执行结果为：{}'.format(check_list[i][0].split('：')[0], status_code1))
                # 检查文件是否上传成功到服务端
                touch_file = fun.search('/opt/pkt', 'txt', 'BG8010Server')
                log.warning('检查服务端/opt/pkt/目录下所有以txt结尾的文件列表为：{}'.format(touch_file))
                # assert '1.txt' in touch_file

                status_code2 = fun.cmd(step_2, 'BG8010Client')
                log.warning('步骤二:{}的命令执行结果为：{}'.format(check_list[i][1].split('：')[0], status_code2))
                # 检查文件是否下载成功到客户端
                touch_file = fun.search('/opt/pkt', 'txt', 'BG8010Client')
                log.warning('检查客户端/opt/pkt/目录下所有以txt结尾的文件列表为：{}'.format(touch_file))
                # assert '1.txt' in touch_file

                status_code3 = fun.cmd(step_3, 'BG8010Client')
                log.warning('步骤三:{}的命令执行结果为：{}'.format(check_list[i][2].split('：')[0], status_code3))
                # 客户端 ssh连接

                fun.ssh_BG8010Client.close()
                # fun.ssh_BG8010Server.close()
                status_code = 0

            else:
                log.warning('无{}方式的http请求，请检查用例表格再执行'.format(check_list[i][0]))
                sys.exit(0)
            success_flag = 'success'
            if '放行' == assert_list[i]:
                if status_code != 200:
                    success_flag = 'fail'
                    result_policy_num.append(i)
                    result_check_method.append(check_list[i][0])
                    result_check_url.append(http_url)
                    result_assert.append(assert_list[i])
                    result_code.append(status_code)
                else:
                    success_flag = 'success'
            elif '阻断' == assert_list[i]:
                if status_code == 200:
                    success_flag = 'fail'
                    result_policy_num.append(i)
                    result_check_method.append(check_list[i][0])
                    result_check_url.append(http_url)
                    result_assert.append(assert_list[i])
                    result_code.append(status_code)
                else:
                    success_flag = 'success'
            else:
                log.warning('无此种【{}】预期结果，请检查后再运行'.format(assert_list[i]))
                sys.exit(0)
            log.warning(
                '\n请求url为【{}】预期结果为：{}，实际请求状态码为：{}，执行结果为：{}'.format(http_url, assert_list[i], status_code, success_flag))

            log.warning('清空定制应用策略')
            for con in content_list[i]:
                fun.send(rbmExc, tool.interface().UDA_app_interface(ruleid=con['RuleId']),
                         dutDomain, base_path)
                fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
                del_res2 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
                assert del_res2 == 1

                log.warning('\n检查定制应用策略是否清空')
                re = fun.wait_data(type=3, dut=dut, context=con['RuleId'], flag=False)
                assert str(con['RuleId']) not in re, '清空定制应用策略,custom_app.json文件仍存在ruleid:{},文件内容为：\n{}'.format(
                    con['RuleId'], re)

            log.warning('实时日志打印到文件 d_auto_test\\auto_test_dms\Logs\APP_datatime.txt')
            abs_path = os.path.dirname(os.path.abspath(__file__))
            parent_path = os.path.dirname(abs_path)  # 获得common所在的目录即common的父级目录，也就是auto_test_dms
            log_txt_path = parent_path + '\\Logs\\' + str(version) + '\\APP_case_result\\'
            log_filename = 'APP_' + time.strftime('%Y-%m-%d_%H-%M-%S', t)
            if not os.path.exists(log_txt_path):
                os.makedirs(log_txt_path)
            log_head = '\n--------------------------------------- 第{}行策略执行情况 --------------------------------------- '.format(
                i + 4)
            policy_content = '\n策略内容：{}'.format(content_list[i])
            policy_check = '\n请求方式【{}】所验证的URL为：{}'.format(check_list[i][0], http_url)
            policy_expected = '\n预期结果为：{}'.format(assert_list[i])
            policy_result = '\n实际执行返回码为：{}'.format(status_code)
            policy_re = '\n执行结果为：{}\n\n\n'.format(success_flag)
            with open(log_txt_path + log_filename + '.txt', 'a+') as log_file:
                log_file.write(log_head)
                log_file.write(policy_content)
                log_file.write(policy_check)
                log_file.write(policy_expected)
                log_file.write(policy_result)
                log_file.write(policy_re)
                log_file.flush()

    log.warning('\n移除业务，还原环境')
    fun.send(rbmExc, tool.interface().setAccessconf(prototype=del_tcp, Mode=2), dutDomain, base_path)
    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
    del_res1 = fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    assert del_res1 == 1
    log.warning('\n检查代理策略是否移除成功')
    fun.check_proxy_policy(dut=dut, flag=False)

    # 执行结果处理
    result_dict['policy'] = result_policy_num
    result_dict['method'] = result_check_method
    result_dict['url'] = result_check_url
    result_dict['code'] = result_code
    return result_dict
