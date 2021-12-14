#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/9/1 12:41

import paramiko
import sys
#
# reload(sys)
# sys.setdefaultencoding('utf8')


class Remote_Ops():
    def __init__(self, hostname, ssh_port, username='', password=''):
        self.hostname = hostname
        self.ssh_port = ssh_port
        self.username = username
        self.password = password

    # 密码登入的操作方法
    def ssh_connect_exec(self, cmd):
        try:
            ssh_key = paramiko.SSHClient()
            ssh_key.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_key.connect(hostname=self.hostname, port=self.ssh_port, username=self.username, password=self.password,
                            timeout=10)
        #            paramiko.util.log_to_file('syslogin.log')
        except Exception as e:
            log.warning('Connect Error：ssh %s@%s: %s' % (self.username, self.hostname, e))
            exit()
        stdin, stdout, stderr = ssh_key.exec_command(cmd, get_pty=True)
        # 切换root
        stdin.write(self.password + '\n')
        stdin.flush()
        err_list = stderr.readlines()
        if len(err_list) > 0:
            log.warning('ERROR:' + err_list[0])
            exit()
        #        log.warning stdout.read()
        for item in stdout.readlines()[2:]:
            log.warning(item.strip())
        ssh_key.close()

    # ssh登陆的操作方法
    def ssh_connect_keyfile_exec(self, file_name, cmd):
        try:
            ssh_key = paramiko.SSHClient()
            ssh_key.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_key.connect(hostname=self.hostname, port=self.ssh_port, key_filename=file_name, timeout=10)
        #            paramiko.util.log_to_file('syslogin.log')
        except Exception as e:
            log.warning(e)
            exit()
        stdin, stdout, stderr = ssh_key.exec_command(cmd)
        err_list = stderr.readlines()
        if len(err_list) > 0:
            log.warning('ERROR:' + err_list[0])
            exit()
        for item in stdout.readlines():
            log.warning(item.strip())
        ssh_key.close()


if __name__ == '__main__':
    # 密码登陆的操作方法：
    test = Remote_Ops('10.10.88.13', 22, 'root', '1q2w3e')
    test.ssh_connect_exec('/usr/local/bin/jsac-read-db-num.sh /etc/jsac/agentjsac.new.db ipv4acl')
    # ssh key登陆的操作方法：（需要到root下运行）
    # file_name = '/var/root/.ssh/id_rsa'
    # test1 = Remote_Ops('10.211.55.11', 22)
    # test1.ssh_connect_keyfile_exec(file_name, 'apt-get update')