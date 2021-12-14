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
    from Case_rbm.ftp_check_cmd import index
    from common import fun, tool
    import common.ssh as c_ssh
except Exception as err:
    log.warning(
        '导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误

# del sys.path[0]
from common import baseinfo
from common import clr_env
from common.rabbitmq import *
from data_check import con_ftp

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
proxy_ip = baseinfo.gwClientIp
delePath = baseinfo.ftp_delePath
ftp_ruleid = baseinfo.ftp_ruleid


class Test_ftp_check_delete():

    def setup_method(self):
        clr_env.data_check_setup_met()

    def teardown_method(self):
        clr_env.data_check_teardown_met('ftp', base_path)

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.clr_env = clr_env
        self.action = index.action
        self.host = index.host
        self.port = index.port
        self.username = index.username
        self.password = index.password
        self.upremotePath = index.upremotePath
        self.uplocalPath = index.uplocalPath
        self.downremotePath = index.downremotePath
        self.downlocalPath = index.downlocalPath

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")  # 需要提前在ftp的ftp_del文件夹内新建一个文件，否则会因为没有文件而报错，前一个用例在文件夹中新建文件
    @allure.feature('验证无上传、下载、删除的FTP传输策略')
    def test_ftp_check_delete_a1(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='gw', type='ftp')

        cmd = "ABOR;ACCT;ADAT;ALLO;APPE;AUTH;CCC;CDUP;CONF;CWD;ENC;EPRT;EPSV;FEAT;HELP;LANG;LIST;LPRT;LPSV;MDTM;MIC;" \
              "MKD;MLSD;MLST;MODE;NLST;NOOP;OPTS;PASS;PASV;PBSZ;PORT;PROT;PWD;QUIT;REIN;REST;RMD;RNFR;RNTO;SITE;" \
              "SIZE;SMNT;STAT;STOU;STRU;SYST;TYPE;USER;XCUP;XMKD;XPWD;XRCP;XRMD;XRSQ;XSEM;XSEN"
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='ftpcheck', cmd_data=cmd, check_action=self.action),
                 rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查ftp应用安全策略是否下发成功')
        re = fun.wait_data(type=4, dut='gw', context=ftp_ruleid)
        log.warning('预期包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) in re

        log.warning('1、普通用户登录ftp服务器')
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        assert '220' in fp.getwelcome()

        log.warning('2、普通用户登录ftp服务器，上传文件(上传命令被禁止)')
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result1 = con_ftp.uploadFile(fp, self.upremotePath, self.uplocalPath)
        log.warning('ftp上传文件扩展名为{}，结果为:{}'.format(self.uplocalPath, result1))
        assert result1 == 0

        log.warning('3、登录ftp服务器，下载文件(下载命令被禁止)')
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result2 = con_ftp.downFile(fp, self.downremotePath, self.downlocalPath)
        log.warning('ftp下载(下载命令被禁止)文件扩展名{}为白名单结果为:{}'.format(self.downremotePath, result2))
        assert result2 == 0

        log.warning('4、 登录ftp服务器，删除目录下的文件（删除命令被禁止）')
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result3 = con_ftp.deleallFile(fp, delePath)
        log.warning('ftp删除(删除命令被禁止){}的结果为:{}'.format(delePath, result3))
        assert result3 == 0

        # 检查ftp传输策略是否清空
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delftpcheck'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查网页安全浏览策略是否清空')
        re = fun.wait_data(type=4, dut='gw', context=ftp_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) not in re

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='gw', type='ftp', flag=False)

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证无下载的FTP传输策略')
    def test_ftp_check_delete_a2(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res1 == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='gw', type='ftp')

        cmd = "ABOR;ACCT;ADAT;ALLO;APPE;AUTH;CCC;CDUP;CONF;CWD;DELE;ENC;EPRT;EPSV;FEAT;HELP;LANG;LIST;LPRT;LPSV;MDTM;" \
              "MIC;MKD;MLSD;MLST;MODE;NLST;NOOP;OPTS;PASS;PASV;PBSZ;PORT;PROT;PWD;QUIT;REIN;REST;STOR;RMD;RNFR;RNTO;" \
              "SITE;SIZE;SMNT;STAT;STOU;STRU;SYST;TYPE;USER;XCUP;XMKD;XPWD;XRCP;XRMD;XRSQ;XSEM;XSEN"
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='ftpcheck', cmd_data=cmd, check_action=self.action),
                 rbmDomain,base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert add_res2 == 1

        log.warning('检查ftp应用安全策略是否下发成功')
        re = fun.wait_data(type=4, dut='gw', context=ftp_ruleid)
        log.warning('预期包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) in re

        # 1、登录ftp服务器，用户为白名单用户
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        assert '220' in fp.getwelcome()

        # 2、登录ftp服务器，上传文件
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result1 = con_ftp.uploadFile(fp, self.upremotePath, self.uplocalPath)
        log.warning('ftp上传文件{}的结果为:{}'.format(self.uplocalPath, result1))
        assert result1 == 1

        # 3、登录ftp服务器，下载文件（下载命令被禁止）
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result2 = con_ftp.downFile(fp, self.downremotePath, self.downlocalPath)
        log.warning('ftp下载（下载命令不在白名单）文件{}的结果为:{}'.format(self.downremotePath, result2))
        assert result2 == 0

        # 4、 登录ftp服务器，删除目录下的文件（允许删除命令）
        fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result3 = con_ftp.deleallFile(fp, delePath)
        log.warning('ftp删除（允许删除命令）文件{}的结果为:{}'.format(delePath, result3))
        assert result3 == 1

        # 检查ftp传输策略是否清空
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delftpcheck'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res2 == 1

        log.warning('检查网页安全浏览策略是否清空')
        re = fun.wait_data(type=4, dut='gw', context=ftp_ruleid, flag=False)
        log.warning('预期不包含内容：{}'.format(ftp_ruleid))
        log.warning('查询ftp.json命令返回值：\n{}'.format(re))
        assert str(ftp_ruleid) not in re

        # 移除策略，还原环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp'), rbmDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        assert del_res1 == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='gw', type='ftp', flag=False)

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()

        fun.rbm_close()
        fun.ssh_close('gw')
