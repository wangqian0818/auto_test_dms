'''
修订人：王谦
修订时间：2021/06/28
修订内容：新增方法：get_dut_version() 实现html的log中显示当前设备的组件版本号

修订人：李皖秋
修订时间：2021/07/22
修订内容：增加函数get_nginx_worker，获取nginx的子进程id

修订人：王谦
修订时间：2021/09/02
修订内容：新增方法：get_db_num()，通过数据库 查询某张表存在的策略条数

修订人：王谦
修订时间：2021/10/29
修订内容：新增方法：get_proxyfile_cmd()，新管控添加了代理文件，此方法获取文件路径和文件名，并返回cat查询命令

'''
# encoding='utf-8'

try:
    import os, sys, time
except Exception as err:
    print('导入CPython内置函数库失败!错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
import logging

log = logging.getLogger(__name__)
base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 获取当前项目文件夹
base_path = base_path.replace('\\', '/')
sys.path.insert(0, base_path)  # 将当前目录添加到系统环境变量,方便下面导入版本配置等文件
try:
    import common.pcap as c_pacp
    import common.rabbitmq as c_rbm
    import common.ssh as c_ssh
    import common.baseinfo as baseinfo
except Exception as err:
    log.warning(
        '导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
qos_port = baseinfo.qos_port

ssh_gw = c_ssh.ssh(baseinfo.gwManageIp, baseinfo.gwUser, baseinfo.gwPwd)
ssh_c = c_ssh.ssh(baseinfo.clientIp, baseinfo.clientUser, baseinfo.clientPwd)
ssh_s = c_ssh.ssh(baseinfo.serverIp, baseinfo.serverUser, baseinfo.serverPwd)
ssh_vlanA = c_ssh.ssh(baseinfo.vlanAIp, baseinfo.vlanAUser, baseinfo.vlanAPwd)
ssh_vlanB = c_ssh.ssh(baseinfo.vlanBIp, baseinfo.vlanBUser, baseinfo.vlanBPwd)
rbm = c_rbm.rabbitmq(baseinfo.rbmIp, baseinfo.rbmWebUser, baseinfo.rbmWebPwd, base_path)
ssh_FrontDut = c_ssh.ssh(baseinfo.BG8010FrontIp, baseinfo.BG8010FrontUser, baseinfo.BG8010FrontPwd)
ssh_BackDut = c_ssh.ssh(baseinfo.BG8010BackIp, baseinfo.BG8010BackUser, baseinfo.BG8010BackPwd)
ssh_BG8010Client = c_ssh.ssh(baseinfo.BG8010ClientIp, baseinfo.BG8010ClientUser, baseinfo.BG8010ClientPwd)
ssh_BG8010Server = c_ssh.ssh(baseinfo.BG8010ServerIp, baseinfo.BG8010ServerUser, baseinfo.BG8010ServerPwd)
ssh_httpServer = c_ssh.ssh(baseinfo.http_server_op_ip, baseinfo.http_server_user, baseinfo.http_server_pass)
log.warning('base_path: ' + str(base_path))
mac = ['gw', 'c', 's', 'FrontDut', 'BackDut', 'BG8010Client', 'BG8010Server', 'httpServer', 'vlanA', 'vlanB']

# appid
http_appid = baseinfo.http_appid
http_post_appid = baseinfo.http_post_appid
tcp_appid = baseinfo.tcp_appid
tcp_ssh_appid = baseinfo.tcp_ssh_appid
smtp_appid = baseinfo.smtp_appid
pop3_appid = baseinfo.pop3_appid
ftp_appid = baseinfo.ftp_appid
app_appid = baseinfo.app_appid

# 代理端口
http_proxy_port = baseinfo.http_proxy_port
smtp_proxy_port = baseinfo.smtp_proxy_port
pop3_proxy_port = baseinfo.pop3_proxy_port
ftp_proxy_port = baseinfo.ftp_proxy_port


def cmd(cmd='', domain='', thread=0, timeout=None, list_flag=False):  # cmd执行函数
    if not cmd:
        log.warning('请输入cmd指令!')
        sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
    if domain not in mac:
        log.warning('请输入有效的ssh主机代号!')
        sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
    ssh_name = 'ssh_' + str(domain)
    return globals()[ssh_name].cmd(cmd=cmd, thread=thread, timeout=timeout,
                                   list_flag=list_flag)  # 调用globals()把文本名变成object对象


def ssh_close(domain=1):  # ssh连接关闭
    if domain not in mac:
        log.warning('请输入有效的ssh主机代号!')
        sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
    ssh_name = 'ssh_' + str(domain)
    return globals()[ssh_name].close()  # 调用globals()把文本名变成object对象


def search(path, end, domain=1):  # 查找文件
    if domain not in mac:
        log.warning('请输入有效的ssh主机代号!')
        sys.exit(0)
    ssh_name = 'ssh_' + str(domain)
    return globals()[ssh_name].search(path, end)


# 从远程服务器读取文件到本地
def read(path='', fun='read', mode='r', text='', domain=1):
    if domain not in mac:
        log.warning('请输入有效的ssh主机代号!')
        sys.exit(0)
    ssh_name = 'ssh_' + str(domain)
    return globals()[ssh_name].open(path, fun, mode, text)


def send(exc, method, domain, path):  # 向Rabbitmq发送信息
    if (not exc) or (not method) or (not domain):
        log.warning('请输入有效的Rabbitmq发送信息参数!')
        sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
    rbm.send(exc, method, domain, path)


def rbm_close():  # 关闭Rabbitmq连接
    rbm.close()


def pkt_capture(iface, filter_, num, pkt_name):  # 开启抓包，只获取命令，不运行
    capture_pkt = "python3 /opt/pkt/sniff.py %s %s %d /opt/pkt/%s" % (iface, filter_, num, pkt_name)
    # capture_pkt = os.system('python E:/卓讯/自动化测试/auto_test/pkt_server/sniff.py %s %s %d %s'%(iface, filter_, num, pkt_name))
    return capture_pkt


def pkt_send(iface, num, pkt_name):  # 发包命令
    # proto=pkt_name.split('__')
    # send_pkt="tcpreplay -i %s -l %d /opt/pkt/%s/%s"%(iface,num,proto,pkt_name)
    send_pkt = "tcpreplay -i %s -l %d /opt/pkt/%s" % (iface, num, pkt_name)
    return send_pkt


def pkt_read(pkt_name, pkt_id):  # 解析报文，返回标记字段，只获取命令，不运行
    read_pkt = "python3 /opt/pkt/read.py /opt/pkt/%s %d" % (pkt_name, pkt_id)
    # read_pkt = os.system('python E:/卓讯/自动化测试/auto_test/pkt_server/read.py %s %d'%(pkt_name,pkt_id))
    return read_pkt


def mss_read(pkt_name, pkt_id):  # 解析报文，返回标记字段，只获取命令，不运行
    read_mss = "python3 /opt/pkt/read_mss.py /opt/pkt/%s %d" % (pkt_name, pkt_id)
    # read_pkt = os.system('python E:/卓讯/自动化测试/auto_test/pkt_server/read.py %s %d'%(pkt_name,pkt_id))
    return read_mss


def vxlan_read(pkt_name, pkt_id):  # 解析报文，返回标记字段，只获取命令，不运行
    read_vxlan = "python3 /opt/pkt/read_vxlan.py /opt/pkt/%s %d" % (pkt_name, pkt_id)
    # read_pkt = os.system('python E:/卓讯/自动化测试/auto_test/pkt_server/read.py %s %d'%(pkt_name,pkt_id))
    return read_vxlan


# def pid_kill(cap_pcap):
# 	# 判断抓包程序是否停止，如果进程还在则停止
# 	pid = cmd(f'ps -ef | grep python | grep {pcap_dip}', 's')
# 	log.warning(pid)
# 	if (cap_pcap in pid):
# 		# 获取进程ID
# 		pid = pid.split()[1]
# 		log.warning(pid)
# 		cmd("kill -9 %s" % pid, "s")

def pid_kill(content, process='python', non_content='bash', gw='s'):
    # 判断抓包程序是否停止，如果进程还在则停止
    cmd1 = f'ps -ef | grep {process} |grep -v grep'
    if process == 'python':
        cmd1 = f'ps -ef | grep {process} | grep {pcap_dip} | grep {content} |grep -v grep'
    while True:
        a = cmd(cmd1, gw)
        log.warning('命令为：{}'.format(cmd1))
        log.warning('命令获取的结果为：{}'.format(a))
        ls = a.split('\n')
        log.warning('将结果分割后的列表为：{}'.format(ls))
        for pro in ls:
            # if 'bash' in pro:
            # 	return
            if content in pro and non_content not in pro:
                kpid = pro.split()[1]
                log.warning('kpid: ' + kpid)
                cmd("kill -9 %s" % kpid, gw)
            elif non_content in pro:
                continue
        break


def iperf_kill():
    # 判断iperf程序是否停止，如果进程还在则停止
    pid = cmd(f'ps -ef | grep iperf3 | grep {qos_port}', 's')
    log.warning('pid:' + pid)
    if ('iperf3' in pid):
        # 获取进程ID
        pid = pid.split()[1]
        log.warning('pid:' + pid)
        cmd("kill -9 %s" % pid, "s")


# 针对selabel模块获取category字段
def cipso_category(a, b):
    value = ''
    for i in range(a, b):
        value = value + ' ' + str(i)
        if i == b - 1:
            return value


def pkt_scp(scp_name, scp_dip):  # scp上传命令
    scp_pkt = f"sshpass -p {baseinfo.serverPwd} scp /opt/pkt/%s root@%s:/opt/pkt" % (scp_name, scp_dip)
    return scp_pkt


def pkt_wget(wget_name, wget_dip):  # wget命令
    wget_pkt = "wget %s /opt/pkt/%s" % (wget_name, wget_dip)
    return wget_pkt


# 获取qos打流的速率
def qos_speed(file, s_txt, qbucket='p'):
    with open(file, 'w') as f:
        f.write(s_txt)

    result = []
    with open(file, 'r') as f:
        for line in f:
            result.append(list(line.strip('\n').split(',')))

    if qbucket == 'p':
        result1 = result[-24:-28]
        speed_list = []
        for i in result1:
            str_i = str(i)
            p_speed = str_i.split()[6]
            speed_list.append(p_speed)
            log.warning(speed_list)
        return speed_list
    elif qbucket == 's':
        result1 = str(result[-30])
        s_speed = result1.split()[5]
        return s_speed


# 判断当前配置是否存在或不存在,flag为True则表示存在检查，False为不存在检查
# type=1：netstat -anp |grep tcp
# type=2：netstat -anp |grep udp
# type=3：cat /etc/jsac/http.json
# type=4：cat /etc/jsac/ftp.json
# type=5：cat /etc/jsac/mail.json
def wait_data(command=None, dut=None, context=None, name='进程', number=100, timeout=0.1, flag=True, type=None):
    if type is not None:
        if 1 == type:
            command = 'netstat -ntlp'
        elif 2 == type:
            command = 'netstat -nulp'
        elif 3 == type:
            command = 'cat /etc/jsac/http.json'
        elif 4 == type:
            command = 'cat /etc/jsac/ftp.json'
        elif 5 == type:
            command = 'cat /etc/jsac/mail.json'
        elif 6 == type:
            command = 'tupleacl --get'
        elif 7 == type:
            command = 'iptables -t mangle -nL'
        elif 8 == type:
            command = 'cat /etc/jsac/keyword.json'
        elif 9 == type:
            command = 'cat /etc/jsac/custom_app.json'
        else:
            log.warning('check_data工具方法中没有该类型，请检查后再运行')
            sys.exit('0')
    else:
        command = command
    # log.warning('查询命令为：{}'.format(command))
    try:
        # 发送该命令到指定设备
        re = cmd(command, dut)
        if context is not None:
            tmp = 0
            # 检查context是否存在命令返回值中
            if flag:
                while str(context) not in re:
                    if tmp < number:
                        time.sleep(timeout)
                        tmp += 1
                        log.warning('这是{}的第{}次等待'.format(name, tmp))
                        re = cmd(command, dut)
                        log.warning(re)
                    else:
                        log.warning('{}检查结果失败'.format(name))
                        return re
            # 检查context是否不存在命令返回值中
            else:
                while str(context) in re:
                    if tmp < number:
                        log.warning(re)
                        time.sleep(timeout)
                        tmp += 1
                        log.warning('这是{}的第{}次等待'.format(name, tmp))
                        re = cmd(command, dut)
                    else:
                        log.warning('{}检查结果失败'.format(name))
                        return re
        else:
            return re
    except Exception as err:
        log.warning('命令 {} 检查失败，报错：{}'.format(command, err))
    return re


# 判断nginx的进程是否是24个，即判断nginx进程启动是否成功
def nginx_worker(command, device, context, non_context1='nginx: worker process is shutting down',
                 non_context2='systemctl reload nginx_kernel', name='进程', number=300, timeout=0.1):
    a = cmd(command, device)
    # log.warning('检查当前nginx的worker进程数，第一次获取的结果为：{}'.format(a))
    tmp = 0
    num = 0
    res = 0
    time.sleep(5)
    while num != 24:
        if tmp < number:
            num = 0  # 每次循环，进程数需重新置为0
            time.sleep(timeout)
            tmp += 1
            # log.warning('这是{}的第{}次等待'.format(name, tmp))
            b = cmd(command, device)
            # log.warning('检查nginx的worker进程数：\n' + b)
            if non_context2 in b:
                continue
            else:
                c = b.split('\n')
                for i in c:
                    if context in i and non_context1 not in i:
                        num += 1
                # log.warning('当前有{}个{}启动成功'.format(num, name))
            if num == 24:
                log.warning('nginx的{}个{}全部启动成功'.format(num, name))
                res = 1
                break
        else:
            log.warning('{}启动失败'.format(name))
            break
    return res


# 用于获取nginx子进程的id号，返回值为列表格式
def get_nginx_worker(str, split_str='root', context='worker', non_context='nginx: worker process is shutting down'):
    resultList = []
    list = str.split(split_str)
    for i in list:
        if context in i and non_context not in i:
            # log.warning(i.strip(' ').strip('\n').split(' '))
            workerID = i.strip(' ').strip('\n').split(' ')[0]
            resultList.append(workerID)
    return resultList


# 获取设备版本号，并写入到文件dut_version.txt
def get_dut_version(case):
    log.warning('获取设备版本号，并写入到文件dut_version.txt')
    result_file = base_path + r'/auto_test/dut_version.txt'
    # 清空文件： result_temp.txt
    with open(result_file, 'w') as file:
        file.seek(0)
        file.truncate()
    with open(result_file, 'a') as file:
        # 包含iso的用例均为隔离的用例
        if 'iso' in case:
            ssh_FrontDut.connect()
            ssh_BackDut.connect()
            # 隔离的前置机查询
            log.warning('-------------------------- 隔离前置机版本号 -----------------------------')
            file.write('---------------------------- 隔离前置机版本号 ---------------------------\n')
            re = cmd('rpm -qa | grep agentjsac', 'FrontDut')
            assert re is not None, '查询 agentjsac 失败'
            file.write(re)
            re = cmd('rpm -qa | grep driver', 'FrontDut')
            assert re is not None, '查询 driver 失败'
            file.write(re)
            re = cmd('rpm -qa | grep libhostapi', 'FrontDut')
            assert re is not None, '查询 libhostapi 失败'
            file.write(re)
            re = cmd('rpm -qa | grep tsthostapi', 'FrontDut')
            assert re is not None, '查询 tsthostapi 失败'
            file.write(re)
            re = cmd('rpm -qa | grep nginx', 'FrontDut')
            assert re is not None, '查询 nginx 失败'
            file.write(re)
            re = cmd('/usr/local/proxyjsac/jsac_proxy -v', 'FrontDut')
            assert re is not None, '查询隔离版本失败'
            file.write(re)

            # 隔离的后置机查询
            log.warning('-------------------------- 隔离后置机版本号 -------------------------------')
            file.write('--------------------------- 隔离后置机版本号 ----------------------------\n')
            re = cmd('rpm -qa | grep agentjsac', 'BackDut')
            assert re is not None, '查询 agentjsac 失败'
            file.write(re)
            re = cmd('rpm -qa | grep driver', 'BackDut')
            assert re is not None, '查询 driver 失败'
            file.write(re)
            re = cmd('rpm -qa | grep libhostapi', 'BackDut')
            assert re is not None, '查询 libhostapi 失败'
            file.write(re)
            re = cmd('rpm -qa | grep tsthostapi', 'BackDut')
            assert re is not None, '查询 tsthostapi 失败'
            file.write(re)
            re = cmd('rpm -qa | grep nginx', 'BackDut')
            assert re is not None, '查询 nginx 失败'
            file.write(re)
            re = cmd('/usr/local/proxyjsac/jsac_proxy -v', 'BackDut')
            assert re is not None, '查询隔离版本失败'
            file.write(re)
            ssh_FrontDut.close()
            ssh_BackDut.close()
        else:
            ssh_gw.connect()
            log.warning('------------------------- 网关设备版本号 ------------------------------')
            file.write('-------------------------- 网关设备版本号 -----------------------------\n')
            re = cmd('rpm -qa | grep agentjsac', 'gw')
            assert re is not None, '查询 agentjsac 失败'
            file.write(re)
            re = cmd('rpm -qa | grep driver', 'gw')
            assert re is not None, '查询 driver 失败'
            file.write(re)
            re = cmd('rpm -qa | grep libhostapi', 'gw')
            assert re is not None, '查询 libhostapi 失败'
            file.write(re)
            re = cmd('rpm -qa | grep tsthostapi', 'gw')
            assert re is not None, '查询 tsthostapi 失败'
            file.write(re)
            re = cmd('rpm -qa | grep nginx', 'gw')
            assert re is not None, '查询 nginx 失败'
            file.write(re)
            ssh_gw.close()


'''
通过数据库 查询某张表存在的策略条数
使用的shell脚本：jsac-read-db-num.sh，在之前查库的脚本（jsac-read-db.sh）上做了修改，使用该功能需要添加该脚本，脚本可以在SVN下载
默认查询前置机的ACL策略数
'''


def get_db_num(dut='FrontDut', db='ipv4acl'):
    # 通过 tupleacl --get  查询当前存在的策略条数
    # ori_acl_re = fun.cmd('tupleacl --get', 'FrontDut')
    # log.warning('命令_{} 的返回值: \n{}\n-------------------------------------------------'.format(
    #     'tupleacl --get', ori_acl_re))
    # exist_policy_num = int(ori_acl_re.split('\n')[0].split(' ')[1])

    # 通过数据库 检查该表存在的策略条数
    try:
        commond = '/usr/local/bin/jsac-read-db-num.sh /etc/jsac/agentjsac.new.db ' + db
        res = cmd(commond, dut)
        # log.warning('命令_{} 的返回值: \n{}\n-------------------------------------------------'.format(cmd, res))
        exist_policy_num = int(res[-1])
    except Exception as err:
        log.warning('需要检查设备(如果是隔离设备只需要检查前置机)是否存在脚本/usr/local/bin/jsac-read-db-num.sh\n命令执行错误，报错消息为：{}\n'.format(err))
        exit(0)
    return exist_policy_num


# 新管控添加了代理文件，此方法获取文件路径和文件名，并返回cat查询命令
# dut='gw'/'FrontDut'/'BackDut'   分别代表网关，前置机和后置机
# type='http'/'ftp'/'smtp'/'pop3'        分别代表http,ftp,mail代理类型
# 返回内容为查询代理文件的命令，类似：cat /etc/jsac/http_proxy/1_2287_http.stream
# 网关的代理文件名设计为：appid_代理端口_类型.stream
# 隔离的代理文件名设计为：appid_65/66_类型.stream     A主机为65，B主机为66
def get_proxyfile_cmd(type='http', dut='gw', mode=2, app_id=None, p_port=None):
    if 'http' in type:
        dir = 'http_proxy'
    else:
        dir = 'other_proxy'
    if mode == 1:  # 透明代理
        if 'http' == type:
            appid = http_appid
            proxy_port = baseinfo.http_server_port
        elif 'http_post' == type:
            appid = http_appid
            proxy_port = baseinfo.http_server_port_file
            type = 'http'
        elif 'ftp' == type:
            appid = ftp_appid
            proxy_port = baseinfo.ftp_dport
        elif 'smtp' == type:
            appid = smtp_appid
            proxy_port = baseinfo.smtp_server_port
        elif 'pop3' == type:
            appid = pop3_appid
            proxy_port = baseinfo.pop3_server_port
        elif 'tcp' == type:
            appid = tcp_appid
            proxy_port = baseinfo.http_server_port
            type = ''
        elif 'udp' == type:
            appid = baseinfo.udp_appid
            proxy_port = baseinfo.http_server_port
            type = ''
        else:
            log.warning('不存在该类型的代理策略')
            sys.exit(0)
    else:
        if 'http' == type:
            appid = http_appid
            proxy_port = http_proxy_port
        elif 'http_post' == type:
            appid = http_appid
            proxy_port = baseinfo.http_server_port_file
            type = 'http'
        elif 'ftp' == type:
            appid = ftp_appid
            proxy_port = ftp_proxy_port
        elif 'smtp' == type:
            appid = smtp_appid
            proxy_port = smtp_proxy_port
        elif 'pop3' == type:
            appid = pop3_appid
            proxy_port = pop3_proxy_port
        elif 'tcp' == type:
            appid = tcp_appid
            proxy_port = http_proxy_port
            type = ''
        elif 'udp' == type:
            appid = baseinfo.udp_appid
            proxy_port = baseinfo.http_proxy_port
            type = ''
        else:
            log.warning('不存在该类型的代理策略')
            sys.exit(0)

    if app_id is not None:
        appid = app_id
    if p_port is not None:
        proxy_port = appid
    if 'FrontDut' == dut:
        proxy_port = 65
    elif 'BackDut' == dut:
        proxy_port = 66
    proxy_filename = str(appid) + '_' + str(proxy_port) + '_' + type + '.stream'
    commond = 'cat /etc/jsac/' + dir + '/' + proxy_filename
    return commond


# 代理策略的下发和移除，检查内容是一样的，所以封装成一个方法，所有用例调用即可
def check_proxy_policy(dut='gw', type='http', flag=True, mode=2, appid=None, p_ip=None, p_port=None):
    proxy_port = ''

    if 'gw' == dut:
        proxy_ip = baseinfo.gwClientIp
    else:
        proxy_ip = baseinfo.BG8010FrontOpeIp

    if mode == 1:  # 透明代理
        if 'http' == type:
            proxy_port = baseinfo.http_server_port
        elif 'http_post' == type:
            proxy_port = baseinfo.http_server_port_file
        elif 'ftp' == type:
            proxy_port = baseinfo.ftp_dport
        elif 'smtp' == type:
            proxy_port = baseinfo.smtp_server_port
        elif 'pop3' == type:
            proxy_port = baseinfo.pop3_server_port
        elif 'tcp' == type:
            proxy_port = baseinfo.http_server_port
        elif 'udp' == type:
            proxy_port = baseinfo.http_server_port
        else:
            log.warning('check_proxy_policy方法中的mode检查失败，请确认后再运行')
        if 'gw' == dut:
            proxy_ip = baseinfo.http_server_ip
        else:
            proxy_ip = baseinfo.BG8010ServerOpeIp
    else:
        if 'http' == type:
            proxy_port = baseinfo.http_proxy_port
        elif 'http_post' == type:
            proxy_port = baseinfo.http_server_port_file
        elif 'ftp' == type:
            proxy_port = baseinfo.ftp_proxy_port
        elif 'smtp' == type:
            proxy_port = baseinfo.smtp_proxy_port
        elif 'pop3' == type:
            proxy_port = baseinfo.pop3_proxy_port
        elif 'tcp' == type:
            proxy_port = baseinfo.http_proxy_port
        elif 'udp' == type:
            proxy_port = baseinfo.http_proxy_port
        else:
            log.warning('check_proxy_policy方法中的type类型检查失败，请确认后再运行')
    if p_port is not None:
        proxy_port = p_port
    if p_ip is not None:
        proxy_ip = p_ip

    context = proxy_ip + ':' + str(proxy_port)

    # 检查配置下发是否成功
    log.warning('检查代理端口是否监听：{}'.format(context))
    if flag:
        re = wait_data(type=(2 if type == 'udp' else 1), dut=dut, context=context)
        # log.warning('监听端口命令返回值：\n{}'.format(re))
        # log.warning('预期包含内容：{}'.format(context))
        assert context in re, '没有包含预期内容{}，实际监听端口命令返回值为：\n{}'.format(context, re)
    else:
        re = wait_data(type=(2 if type == 'udp' else 1), dut=dut, context=context, flag=False)
        # log.warning('监听端口命令返回值：\n{}'.format(re))
        # log.warning('预期不包含内容：{}'.format(context))
        assert context not in re, '包含非预期内容{}，实际监听端口命令返回值为：\n{}'.format(context, re)
    log.warning('端口监听检查通过')

    log.warning('检查代理文件和内容是否正确')
    commond = get_proxyfile_cmd(type=type, dut=dut, mode=mode, app_id=appid, p_port=p_port)
    log.warning('查询命令为：' + commond)
    # log.warning('检查内容为：' + context)
    re1 = cmd(cmd=commond, domain=dut)
    #log.warning('代理文件内容为：\n' + re1)
    if flag:
        assert context in re1, '没有包含预期监听端口{}，实际代理文件内容为：\n{}'.format(context, re1)
    else:
        assert context not in re1, '包含非预期监听端口{}，实际代理文件内容为：\n{}'.format(context, re1)
    log.warning('代理文件检查通过')


def change_check_labelStr(label):
    """
    将标记转正字符串，以便于跟tupleacl--get查出的结果对比
    :param label:
    :return:
    """
    # 12/1/0/1-100/1-100/0xff,0xff,0xff,0xff
    # DOI/Type/Match/Sensitivity/Integrity/Cat
    labelstr = ''
    for v in list(label.values())[0].values():
        labelstr += '/' + str(v)
    else:
        labelstr = labelstr[1:]
    return labelstr


def send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=None, tgLabel=None, rvMtLabel=None,
               rvTgLabel=None, L4protocol='tcp'):
    '''
    下发标记策略公用方法
    :param self:
    :param tool:
    :param rbmDomain:
    :param rbmExc:
    :param clientOpeIp:
    :param serverOpeIp:
    :param mtLabel:
    :return:
    '''
    # 服务端通过RabbitMQ下发策略业务配置并检查结果
    log.warning('设备通过RabbitMQ下发策略业务访问配置：')
    send(rbmExc, tool.interface().cipso_agent_interface(prototype='addAgent', L4protocol=L4protocol), rbmDomain,
         base_path)
    # 检查业务配置是否下发成功
    log.warning('检查业务配置是否下发成功：')
    re = wait_data(type=6, dut='gw', context=clientOpeIp, number=100)
    log.warning('预期包含内容：{}'.format(serverOpeIp))
    log.warning('监听端口命令返回值：\n{}'.format(re))
    assert serverOpeIp in re and clientOpeIp in re
    # 下发安全标记策略
    log.warning('设备通过RabbitMQ下发安全标记策略：')
    send(rbmExc, tool.interface().cipso_selabel_interface(prototype='addSelabel', mtLabel=mtLabel, tgLabel=tgLabel,
                                                          rvMtLabel=rvMtLabel, rvTgLabel=rvTgLabel),
         rbmDomain, base_path)
    # 检查安全标记策略是否下发成功
    log.warning('检查设备安全标记策略是否下发成功：')
    mtLabelStr = change_check_labelStr(mtLabel)
    log.warning(mtLabelStr)
    re = wait_data(type=6, dut='gw', context=mtLabelStr, number=100)
    log.warning('预期包含内容：{}'.format(mtLabelStr))
    log.warning('监听端口命令返回值：\n{}'.format(re))
    assert mtLabelStr in re


def delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel):
    '''
    删除标记策略公用方法
    :param self:
    :param tool:
    :param rbmDomain:
    :param rbmExc:
    :param clientOpeIp:
    :param serverOpeIp:
    :param mtLabel:
    :return:
    '''
    # 设备移除策略
    mtLabelStr = change_check_labelStr(mtLabel)
    log.warning('设备移除策略')
    send(rbmExc, tool.interface().cipso_selabel_interface(prototype='delSelabel'), rbmDomain, base_path)
    re = wait_data(type=6, dut='gw', context=mtLabelStr, number=100, flag=False)
    log.warning('预期包含内容：{}'.format(mtLabelStr))
    log.warning('监听端口命令返回值：\n{}'.format(re))
    assert mtLabelStr not in re
    # 设备移除业务配置
    log.warning('设备移除业务配置')
    send(rbmExc, tool.interface().cipso_agent_interface(prototype='delAgent'), rbmDomain, base_path)
    re = wait_data(type=6, dut='gw', context=clientOpeIp, number=100, flag=False)
    log.warning('预期包含内容：{}'.format(serverOpeIp))
    log.warning('监听端口命令返回值：\n{}'.format(re))
    assert serverOpeIp not in re and not clientOpeIp in re


def client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap, c_iface, c_num, c_pcap, read_name, read_id,
                           expect):
    '''
    客户端tcpreplay发包，服务端抓包并分析结果的公共方法
    :param cap_iface: 接口名称
    :param cap_filter: 过滤规则
    :param cap_num: 抓包数量
    :param cap_pcap: 报文命名
    :param c_iface: 发送报文接口
    :param c_num: 发送报文数量
    :param c_pcap: 发送报文名称
    :param read_name:保存的报文名称 这里读取的报文名称和上面抓包的保存报文名称应该一致
    :param read_id: 要读取的包的序号
    :param expect: 预期结果
    :return:
    '''
    # 服务端抓取报文
    cmd(f"rm -rf /opt/pkt/{cap_pcap}", 's')
    pre_cfg = pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
    log.warning('服务端设置抓取报文：{}'.format(pre_cfg))
    cmd(pre_cfg, 's', thread=1)
    log.warning('step wait 20s')
    time.sleep(20)
    # 客户端发送报文
    send_cmd = pkt_send(c_iface, c_num, c_pcap)
    log.warning('客户端发送报文：{}'.format(send_cmd))
    cmd(send_cmd, 'c')
    # 检查报文是否存在
    pcap_file = search('/opt/pkt', 'pcap', 's')
    pid_kill(cap_pcap)
    log.warning('服务端检查报文是否存在：{}'.format(pcap_file))
    assert cap_pcap in pcap_file
    # 读取并分析报文
    read_cmd = pkt_read(read_name, read_id)
    read_re = cmd(read_cmd, 's')
    log.warning('读取并分析报文：{}'.format(read_re))
    assert expect == read_re
