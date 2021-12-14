#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/11/29 16:09
import logging
# 将表格中读取格式过的内容进行再判断，并发送到设备端
import os
import sys
import time

from common import baseinfo, fun, clr_env, deal_excel_case
from common.read_excel import read_xls

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

http_ruleid = baseinfo.http_ruleid
ftp_ruleid = baseinfo.ftp_ruleid
smtp_ruleid = baseinfo.smtp_ruleid

ftp_ip = baseinfo.ftp_ip
ftp_dport = baseinfo.ftp_dport
ftp_user = baseinfo.ftp_user
ftp_pass = baseinfo.ftp_pass
ftp_downremotePath = baseinfo.ftp_downremotePath
ftp_downlocalPath = baseinfo.ftp_downlocalPath
ftp_upremotePath = baseinfo.ftp_upremotePath
ftp_uplocalPath = baseinfo.ftp_uplocalPath
ftp_uploadDirPath = baseinfo.ftp_uploadDirPath
# ftp_delePath = baseinfo.ftp_delePath  # ftp删除的路径

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
title = '读表执行用例，业务有效性测试'
context = '测试内容-content'
file = '1.xls'
attach_file = mail_attach + file

start_time = time.time()
t = time.localtime(start_time)


# 执行策略的函数，
# data_type: 【http、ftp、mail】
# dut: 【gw、Front】
# 执行的用例行数：【all、行号（对应用例表中的行号）】
def send_policy(data_type=['http'], dut='gw', policy_num='all'):
    policy_dict = read_xls(data_type=data_type)
    # content_list = policy_dict['content']
    # check_list = policy_dict['check']
    # assert_list = policy_dict['assert']
    # log.warning(policy_dict['content'])
    # log.warning(policy_dict['check'])
    # log.warning(policy_dict['assert'])
    if 'gw' == dut:
        proxy_ip = gw_proxy_ip
        fun.ssh_gw.connect()
        clr_env.clear_env()
    elif 'Front' == dut:
        proxy_ip = iso_proxy_ip
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        clr_env.iso_setup_class(dut='FrontDut')
    else:
        log.warning('无设备类型为{}，请检查后再试'.format(dut))
        sys.exit(0)
    if 'http' in data_type:
        http_result_dict = deal_excel_case.http_data_check(policy_num, policy_dict['http'], dut)
    if 'ftp' in data_type:
        ftp_result_dict = deal_excel_case.ftp_data_check(policy_num, policy_dict['ftp'], dut)
    if 'mail' in data_type:
        mail_result_dict = deal_excel_case.mail_data_check(policy_num, policy_dict['mail'], dut)
    if 'keyword' in data_type:
        keyword_result_dict = deal_excel_case.keyword_data_check(policy_num, policy_dict['keyword'], dut)
    if 'app' in data_type:
        app_result_dict = deal_excel_case.app_data_check(policy_num, policy_dict['app'], dut)
    # else:
    #     log.warning('类型为{}的用例暂时没有，请检查后再试'.format(data_type))
    #     sys.exit(0)

    # if 'gw' == dut:
    #     fun.ssh_gw.close()
    #     clr_env.clear_env()
    # elif 'Front' == dut:
    #     fun.ssh_FrontDut.close()
    #     fun.ssh_BackDut.close()
    #     clr_env.iso_setup_class(dut='FrontDut')
    # else:
    #     log.warning('无设备类型为{}，请检查后再试'.format(dut))
    #     sys.exit(0)

    log.warning('=============================================================\n')
    if 'http' in data_type:
        show_result('http', policy_dict, policy_num, http_result_dict)
    if 'ftp' in data_type:
        show_result('ftp', policy_dict, policy_num, ftp_result_dict)
    if 'mail' in data_type:
        show_result('mail', policy_dict, policy_num, mail_result_dict)
    if 'keyword' in data_type:
        show_result('keyword', policy_dict, policy_num, keyword_result_dict)
    if 'app' in data_type:
        show_result('app', policy_dict, policy_num, app_result_dict)

    end_time = time.time()
    log.warning('所有用例，总执行时间为：{}'.format(round(end_time - start_time, 3)))


def show_result(type, policy_dict, policy_num, result_dict):
    if policy_num == 'all':
        all_policy_num = len(policy_dict[type]['assert'])
    else:
        all_policy_num = 1

    log.warning('---------------------------------------------------------------------------------------------')
    if len(result_dict['policy']) == 0:
        log.warning('{}模块共{}条用例全部成功，恭喜恭喜'.format(type, all_policy_num))
    else:
        log.warning('{}模块共{}条用例，失败的用例有{}条，行号及内容为：\n'.format(type, all_policy_num, len(result_dict['policy'])))
        for i in range(len(result_dict['policy'])):
            log.warning(
                '用例表中第{}行用例，请求状态码为：{}'.format(result_dict['policy'][i] + 4, result_dict['code'][i]))


if __name__ == '__main__':
    # data_type 执行用例的类型，包含['http', 'ftp', 'mail', 'keyword', 'app']
    # policy_num 为用例表中的用例行号，执行单条用例的时候就写该用例的行号，用于调试,用例从第四行开始, policy_num='108'
    data_type = ['keyword']
    send_policy(data_type=data_type)
