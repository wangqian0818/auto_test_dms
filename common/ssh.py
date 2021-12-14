#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/3/16 16:59
# 连接设备之后必须要有数据传输，否则关闭会有问题
import logging
import select
import sys

import paramiko

log = logging.getLogger(__name__)


class ssh:

    def __init__(self, host='', name='', passwd='', port=22, timeout=30):
        if (not host) or (not name) or (not passwd):
            log.warning('ssh服务器地址,帐号和密码都不能为空!')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        self.hostname = host
        self.password = passwd
        self.port = port
        self.username = name
        self.timeout = timeout
        self.ssh = ''
        self.channel = ''
        # 实例化对象
        try:
            # 实例化SSHClient
            self.ssh = paramiko.SSHClient()
        except Exception as err:
            log.warning('调用paramiko.SSHClient()创建ssh连接对象失败!错误内容如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        # 将信任的主机添加到host_allow
        try:
            # 自动添加策略，保存服务器的主机名和密钥信息，如果不添加，那么不再本地know_hosts文件中记录的主机将无法连接
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        except Exception as err:
            log.warning('将信任的主机: ' + str(self.hostname) + '添加到host_allow失败!错误内容如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        else:
            # ssh服务器连接状态：0表示初始化完成，1表示连接成功
            self.__state = 0
            log.warning('ssh初始化: ' + str(self.hostname) + '完成!')

    def connect(self):
        log.warning("ssh 连接开始")
        try:
            # 建立连接
            self.ssh.connect(hostname=self.hostname, password=self.password, port=self.port, username=self.username)
            # ssh服务器连接状态
            self.__state = 1
            log.warning('ssh连接主机：' + self.hostname + '  完成!')
        except Exception as err:
            log.warning("连接 {} 失败: {}".format(self.hostname, err))
            return False
            sys.exit(1)
        # 更改连接状态：0表示初始化完成，1表示连接成功
        self.__state = 1
        log.warning('ssh服务器: ' + str(self.hostname) + '连接成功')
        return True

    def cmd(self, cmd='ls -l', thread=0, timeout=0, list_flag=False):
        # 查看连接状态
        if not self.__state:
            log.warning('ssh初始化未完成，程序友好退出')
            sys.exit(1)
        if self.__state == 0:
            log.warning('ssh连接主机{}失败，程序友好退出', self.hostname)
            sys.exit(1)
        # 如果cmd是包含多个命令的list，list_flag=True
        if list_flag:
            # 将列表cmds中的指令用';'连接成一个分号分隔的字符串
            cmd = ';'.join(cmd)

        # 每个命令一个channel
        if thread == 1:
            stdout = self.ssh.get_transport().open_session().exec_command(cmd)
            # stdout.close()
            return None
        else:
            # try:
            stdin, stdout, stderr = self.ssh.exec_command(command=cmd, timeout=20)
            if 'jsac-read-db-num.sh' in cmd:
                res = stdout.readlines()
                new_re = []
                for line in res:
                    new_re.append(line.strip())
                return new_re

            # 从stdout/stderr/stdin获取共享管道
            self.channel = stdout.channel

            # 不需要stdin
            stdin.close()
            # 表示我们将不再写该通道
            self.channel.shutdown_write()

            # 读取stdout / stderr以防止读取块挂起
            stdout_chunks = []
            if list_flag:
                for i in range(len(cmd)):
                    stdout_chunks.append(stdout.channel.recv(65535).decode('utf-8'))
            else:
                stdout_chunks.append(stdout.channel.recv(65535).decode('utf-8'))
            # 分块读取以防止停顿
            while not self.channel.closed or self.channel.recv_ready() or self.channel.recv_stderr_ready():
                # 如果通道过早关闭并且缓冲区中没有数据，则停止。
                got_chunk = False
                readq, _, _ = select.select([stdout.channel], [], [], timeout)
                for c in readq:
                    if c.recv_ready():
                        stdout_chunks.append(stdout.channel.recv(len(c.in_buffer)))
                        got_chunk = True
                    if c.recv_stderr_ready():
                        # 确保读stderr以防止失速
                        stderr.channel.recv_stderr(len(c.in_stderr_buffer))
                        got_chunk = True
                '''
                 1）确保输入缓冲区中至少有2个周期没有数据，以免过早退出（例如，大于200k文件的cat）。
                 2）如果最后一个循环中没有数据到达，请检查是否已经收到退出代码
                 3）检查输入缓冲区是否为空
                 4）退出循环
                '''
                if not got_chunk \
                        and stdout.channel.exit_status_ready() \
                        and not stderr.channel.recv_stderr_ready() \
                        and not stdout.channel.recv_ready():
                    # 表示我们将不再从该 channel 读
                    stdout.channel.shutdown_read()
                    # close the channel
                    stdout.channel.close()
                    break  # 当远端完成并且我们的缓冲区为空时退出

            # log.warning('--------- stdout_chunks:\n{}\n-----------'.format(stdout_chunks))
            b = [str(j) for j in stdout_chunks]
            # log.warning(b)
            out = ''.join(b)
            # log.warning('--------- \n', out)

            # 关闭所有文件描述符
            stdout.close()
            stderr.close()
            return out
        # except Exception as err:
        #     log.warning('发送命令错误：{}'.format(err))
        #     return None

        # if want_exitcode:
        #     # 此时退出代码始终准备就绪
        #     return (''.join(stdout_chunks), stdout.channel.recv_exit_status())
        # return ''.join(stdout_chunks)

    def close(self):
        # 查看连接状态
        if not self.__state:
            log.warning('ssh初始化未完成，程序友好退出')
            sys.exit(1)
        if self.__state == 0:
            log.warning('ssh未连接主机{}，程序友好退出'.format(self.hostname))
            sys.exit(1)
        log.warning("Command done, closing SSH connection")
        self.ssh.close()
        self.channel.close()

    def sftp(self, local_path='', ssh_path='', method='get'):
        '''
        上传和下载文件:操作本方法前!!!不需要!!!连接远程服务器
        调用方式为:实例化类名.sftp('本地路径','远程路径','获取方式')
        local_path为本地路径地址;ssh_path为远程路径地址
        method为操作方式,get为从远程获取文件;put为从本地上传到远程服务器
        '''
        try:
            transport = paramiko.Transport((self.hostname, int(self.port)))
        except Exception as err:
            log.warning('sftp文件传输通道初始化失败!请检查ssh服务器地址和端口号是否正确.\n错误内容如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        try:
            transport.connect(username=self.username, password=self.password)
        except Exception as err:
            log.warning('sftp文件传输通道连接失败!请检查ssh服务器登陆名和密码是否正确.\n错误内容如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
        except Exception as err:
            log.warning('sftp文件传输通道创建失败!请检查网络和服务器状态.\n服务器地址和帐号都没问题.\n错误内容如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        if (not local_path) or (not ssh_path):
            log.warning('本地路径和远程路径都不能为空!')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        if method == 'get':
            try:
                sftp.get(ssh_path, local_path)
            except Exception as err:
                log.warning('错误!!!将远程: ' + str(ssh_path) + '文件下载到本地: ' + str(local_path) + ' 失败!错误内容如下:')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            else:
                log.warning('成功!!!将远程: ' + str(ssh_path) + '文件下载到本地: ' + str(local_path) + ' 完成!')
                sftp.close()  # 及时关闭sftp连接,下次需要重新调用当前方法就可创建新的连接
        elif method == 'put':
            try:
                sftp.put(local_path, ssh_path)
            except Exception as err:
                log.warning('错误!!!将本地: ' + str(local_path) + '文件上传到ssh服务器: ' + str(ssh_path) + ' 失败!错误内容如下:')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            else:
                log.warning('成功!!!将本地: ' + str(local_path) + '文件上传到ssh服务器: ' + str(ssh_path) + ' 完成!')
                sftp.close()  # 及时关闭sftp连接,下次需要重新调用当前方法就可创建新的连接
        else:
            log.warning('sftp操作文件方式只有get(下载文件)和put(上传文件)两种,其它操作无效!\n默认操作方式为get,下载文件.请检查sftp方法的参数是否有误.')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

    def open(self, file_path='', fun='read', mode='r', text=''):
        '''
        读写远程文件:操作本方法前需连接远程服务器
        调用方式为:实例化类名.open('文件路径','操作模式','操作方式')
        file_path为远程文件路径;

        fun为文件操作方式,默认为'read',可选参数及意义如下:
        方法	描述
        read	从文件中读取所有内容
        write	将内容写入文件

        mode为操作模式,默认为'r',可选参数及意义如下:
        模式	描述
        t	文本模式 (默认)。
        x	写模式，新建一个文件，如果该文件已存在则会报错。
        b	二进制模式。
        +	打开一个文件进行更新(可读可写)。
        r	以只读方式打开文件。文件的指针将会放在文件的开头。这是默认模式。
        rb	以二进制格式打开一个文件用于只读。文件指针将会放在文件的开头。这是默认模式。一般用于非文本文件如图片等。
        r+	打开一个文件用于读写。文件指针将会放在文件的开头。
        rb+	以二进制格式打开一个文件用于读写。文件指针将会放在文件的开头。一般用于非文本文件如图片等。
        w	打开一个文件只用于写入。如果该文件已存在则打开文件，并从开头开始编辑，即原有内容会被删除。如果该文件不存在，创建新文件。
        wb	以二进制格式打开一个文件只用于写入。如果该文件已存在则打开文件，并从开头开始编辑，即原有内容会被删除。如果该文件不存在，创建新文件。一般用于非文本文件如图片等。
        w+	打开一个文件用于读写。如果该文件已存在则打开文件，并从开头开始编辑，即原有内容会被删除。如果该文件不存在，创建新文件。
        wb+	以二进制格式打开一个文件用于读写。如果该文件已存在则打开文件，并从开头开始编辑，即原有内容会被删除。如果该文件不存在，创建新文件。一般用于非文本文件如图片等。
        a	打开一个文件用于追加。如果该文件已存在，文件指针将会放在文件的结尾。也就是说，新的内容将会被写入到已有内容之后。如果该文件不存在，创建新文件进行写入。
        ab	以二进制格式打开一个文件用于追加。如果该文件已存在，文件指针将会放在文件的结尾。也就是说，新的内容将会被写入到已有内容之后。如果该文件不存在，创建新文件进行写入。
        a+	打开一个文件用于读写。如果该文件已存在，文件指针将会放在文件的结尾。文件打开时会是追加模式。如果该文件不存在，创建新文件用于读写。
        ab+	以二进制格式打开一个文件用于追加。如果该文件已存在，文件指针将会放在文件的结尾。如果该文件不存在，创建新文件用于读写。

        text为写模式下,要写入的内容
        '''
        if not self.__state:
            log.warning('ssh服务器未连接或连接失败,请执行:实例化类名.connect()连接ssh服务器后再执行当前方法')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        else:
            if not file_path:
                log.warning('请输入要操作的远程文件路径!')
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            try:
                sftp_open = self.ssh.open_sftp()
            except Exception as err:
                log.warning('sftp操作文件通道创建失败!错误内容如下:')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            else:
                try:
                    fun_file = sftp_open.open(file_path, mode)
                except Exception as err:
                    log.warning('文件 ' + str(self.hostname) + ':' + str(file_path) + ' 连接失败!错误内容如下:')
                    log.warning(err)
                    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
                else:
                    if fun == 'read':
                        try:
                            file_text = fun_file.read()  # 如果执行的是读文件操作,就返回文件读取结果
                        except Exception as err:
                            log.warning('文件 ' + str(self.hostname) + ':' + str(file_path) + ' 读取失败!错误内容如下:')
                            log.warning(err)
                            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
                        else:
                            log.warning('文件 ' + str(self.hostname) + ':' + str(file_path) + ' 读取成功!')
                            fun_file.close()  # 执行完毕及时关闭文件连接
                            return file_text
                    elif fun == 'write':
                        if not text:
                            log.warning('当前写入内容为空!!!')
                        try:
                            fun_file.write(text)
                        except Exception as err:
                            log.warning('文件 ' + str(self.hostname) + ':' + str(file_path) + ' 写入失败!错误内容如下:')
                            log.warning(err)
                            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
                        else:
                            log.warning(
                                '向文件: ' + str(self.hostname) + ':' + str(file_path) + ' 中写入: ' + str(text) + ' 成功')
                            fun_file.close()  # 执行完毕及时关闭文件连接
                            return 'ok'  # 写成功返回特定字符串,为了和读操作进行匹配,避免无返回值的空值操作
                    else:
                        log.warning('当前仅支持read和write操作!!!请检查操作方法是否有误.')
                        sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

    def search(self, path='', end=''):
        '''
        搜索(查找)文件:操作本方法前需要连接远程服务器
        调用方式为:实例化类名.search('远程路径','文件后缀')
        path为要搜索的ssh服务器路径,默认搜索主目录下的所有文件和文件夹,并以列表的形式返回
        end为想要返回的文件后缀名,可以留空,意味着返回所有的文件类型
        '''
        if not self.__state:
            log.warning('ssh服务器未连接或连接失败,请执行:实例化类名.connect()连接ssh服务器后再执行当前方法')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        else:
            try:
                sftp_search = self.ssh.open_sftp()
            except Exception as err:
                log.warning('ssh查找文件通道创建失败!请检查网络和ssh服务器地址,端口号,帐号和密码是否有误.\n错误内容如下:')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            else:
                try:  # 查找文件夹
                    if path:
                        file_name = sftp_search.listdir(path)
                    else:
                        file_name = sftp_search.listdir()
                except Exception as err:
                    log.warning('查找路径: ' + str(path) + '下的所有文件和文件夹失败!错误内容如下:')
                    log.warning(err)
                    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
                else:
                    if end:
                        try:  # 查找path目录下以end结尾的文件
                            file_name_0 = []
                            for i in file_name:
                                if i.endswith(end):
                                    file_name_0.append(i)
                            file_name = file_name_0[:]
                        except Exception as err:
                            log.warning('查找路径: ' + str(path) + '下的所有以: ' + str(end) + ' 结尾的文件失败!错误内容如下:')
                            log.warning(err)
                            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
                    return file_name


if __name__ == '__main__':
    # 连接设备之后必须要有数据传输，否则关闭会有问题
    hostname = '10.10.88.47'
    username = "root"
    port = 22
    password = "1q2w3e"
    # password = "3e2b6e75b403c492"
    ssh = ssh(host=hostname, passwd=password, port=port, name=username)
    ssh.connect()
    re = ssh.cmd(cmd='cd /opt/pkt/ && wget http://11.11.11.100:8889/vlanA.pdf')
    # re = ssh.cmd(cmd='ps -ef |grep jsac')
    # cmd = ['cd /opt', 'who', 'pwd', 'ls -ahl']
    # re = ssh.cmd(cmd=cmd, list_flag=True)
    log.warning("re:\n" + re)
    ssh.close()
