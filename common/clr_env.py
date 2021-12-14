# coding:utf-8
import logging
import time

from common import baseinfo
from common import fun, tool

log = logging.getLogger(__name__)
rbmDomain = baseinfo.rbmDomain
FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc

# card_list = [0]
card_clear = [0, 1]


def clear_env(dut='gw'):
    start = time.time()
    clear_env = []
    env_list = [
        "switch-jsac --set --switch on",
        'switch-jsac --set --module 12 --switch off',
        'switch-jsac --set --module 13 --switch off',
        'switch-jsac --set --module 15 --switch off',
        'switch-jsac --set --module 16 --switch off',
        # 'switch-jsac --set --module 17 --switch off',
        "defconf  --action forward",
        "defconf --selabel on",
        "defconf --cycle 15",
        "defconf --ipv4aclcycle 30",
        'defconf --domain off',
        'defconf --netflow off',
        'defconf --ipv4acl off',
        'defconf --syncookie off',
        'defconf --ckoption off',
        'defconf --noflow off',
        'defconf --droperr off',
        'defconf --tcpmss 0'
    ]

    for i in card_clear:
        for j in env_list:
            cmd = f'export cardid={i}&&{j}'
            clear_env.append(cmd)
    for i in clear_env:
        # log.warning('clear_env_cmd:' + i)
        dd = fun.cmd(i, dut)
        # log.warning('clear_env_result:' + dd)
    log.warning("=========================== clear_env 结束 耗时：{}s ==================================".format(
        time.time() - start))


def clear_met_acl(dut='gw'):
    start = time.time()
    clear_met = []

    met_list = [
        "tupleacl --clear",
        "selabel --clear",
        "qos-jsac --clear"
    ]

    for i in card_clear:
        for j in met_list:
            cmd = f'export cardid={i}&&{j}'
            clear_met.append(cmd)
    for i in clear_met:
        log.warning('clear_met_cmd:' + i)
        dd = fun.cmd(i, dut)
        log.warning('clear_met_result:' + dd)
    log.warning("=========================== clear_met_acl 结束 耗时：{}s ==================================".format(
        time.time() - start))


def data_check_setup_met(dut='gw'):
    start = time.time()
    fun.wait_data('ps -ef |grep agentjsac', dut, '/usr/bin/agentjsac -n -c /etc/jsac/agentjsac.config')
    fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    log.warning("=========================== data_check_setup_met 结束 耗时：{}s ==================================".format(
        time.time() - start))


def data_check_teardown_met(protocol, base_path, dut='gw'):
    start = time.time()
    if protocol == 'mail':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delsmtp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
        fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delpop3'), rbmDomain, base_path)
    elif protocol == 'ftp':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp'), rbmDomain, base_path)
    elif protocol == 'http':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp'), rbmDomain, base_path)
    elif protocol == 'tcp_http':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='del_tcp_http'), rbmDomain, base_path)
    else:
        pass
    fun.wait_data('ps -ef |grep nginx', dut, 'nginx: worker process')
    fun.nginx_worker('ps -ef |grep nginx', dut, 'nginx: worker process')
    log.warning(
        "=========================== data_check_teardown_met 结束 耗时：{}s ==================================".format(
            time.time() - start))


def iso_setup_class(dut):
    start = time.time()
    fun.wait_data('ps -ef |grep jsac', dut, 'jsac_master')
    for i in range(4):
        fun.wait_data('ps -ef |grep jsac', dut, f'jsac_worker{i}')
    log.warning(
        "=========================== 设备{}iso_setup_class 结束 耗时：{}s ==================================".format(dut, (
                time.time() - start)))


def iso_teardown_met(protocol, base_path):
    start = time.time()
    if protocol == 'mail':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delsmtp_front'), FrontDomain, base_path)
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delpop3_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
    elif protocol == 'ftp':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp_front'), FrontDomain, base_path)
    elif protocol == 'tcp_http':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='del_tcp_http_front'), FrontDomain, base_path)
    elif protocol == 'http':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
    elif protocol == 'http_post':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front_post'), FrontDomain, base_path)
    elif protocol == 'http_redirect':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_redirect_front'), FrontDomain, base_path)
    elif protocol == 'dns':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='deludp_dns_front'), FrontDomain, base_path)
    elif protocol == 'ssh':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='deltcp_ssh_front'), FrontDomain, base_path)
    elif protocol == 'app_allow':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='del_app_upstream_front'), FrontDomain, base_path)
    elif protocol == 'app_deny':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='del_app_action_front'), FrontDomain, base_path)
    elif protocol == 'app_scp':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='del_app_scp_front'), FrontDomain, base_path)
    elif protocol == 'app_end_deny':
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='del_app_end_deny_front'), FrontDomain, base_path)
    else:
        pass
    fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
    fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
    fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
    fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
    log.warning("=========================== iso_teardown_met 结束 耗时：{}s ==================================".format(
        time.time() - start))


def clear_datacheck(protocol, base_path):
    if protocol == 'http':
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), FrontDomain, base_path)
    elif protocol == 'mail':
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delmailcheck'), FrontDomain, base_path)
    elif protocol == 'ftp':
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delftpcheck'), FrontDomain, base_path)
    fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
    fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')


def verifymod_teardown_met(base_path):
    start = time.time()
    fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delftpcheck'), rbmDomain, base_path)
    fun.cmd('ipauth-jsac --clear', 'gw')
    log.warning(
        "=========================== verifymod_teardown_met 结束 耗时：{}s ==================================".format(
            time.time() - start))
