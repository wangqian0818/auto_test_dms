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
    from Case_rbm.iso_ftp_up_down_dir import index
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
from data_check import con_ftp

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain

proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
# ftp_localDir = baseinfo.ftp_localDir
# ftp_remoteDir = baseinfo.ftp_remoteDir
ftp_uploadDirPath = baseinfo.ftp_uploadDirPath
ftp_downremotePath = '/home/ftp/ftp_auto/ftp_down_dir'
ftp_downlocalPath = 'C:\\Users\\admin\\Desktop\\work\\down_dir\\'


class Test_iso_ftp_up_down_dir():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')

    def teardown_method(self):
        clr_env.iso_setup_class(dut='FrontDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        self.ftp_proxy_port = baseinfo.ftp_proxy_port
        self.ftp_user = baseinfo.ftp_user
        self.ftp_pass = baseinfo.ftp_pass

        # clr_env.iso_setup_class(dut='FrontDut')
        # clr_env.iso_setup_class(dut='BackDut')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的ftp传输策略下载一个文件夹')
    def test_iso_ftp_up_down_dir_a1(self):

        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='ftp')

        # 登录ftp服务器，下载一个文件夹内的所有文件夹
        fp = con_ftp.connect_ftp(proxy_ip, self.ftp_proxy_port, self.ftp_user, self.ftp_pass)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        result = con_ftp.DownDir(fp, ftp_downremotePath, ftp_downlocalPath)
        log.warning('ftp走隔离下载一个文件夹内的所有文件夹结果为:{}'.format(result))
        assert result == 1

        log.warning('移除代理策略，清空环境')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        log.warning('检查代理策略是否移除成功')
        fun.check_proxy_policy(dut='FrontDut', type='ftp', flag=False)

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的ftp传输策略上传一个文件夹')
    def test_iso_ftp_up_down_dir_a2(self):

        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addftp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='ftp')

        # 登录ftp服务器，上传一个文件夹内的所有文件和文件夹
        fp = con_ftp.connect_ftp(proxy_ip, self.ftp_proxy_port, self.ftp_user, self.ftp_pass)
        log.warning('欢迎语是：{}'.format(fp.getwelcome()))
        log.warning('ftp_uploadDirPath:', ftp_uploadDirPath)
        result = con_ftp.uploadFileAll(fp, ftp_uploadDirPath)
        log.warning('ftp走隔离上传一个文件夹内的所有文件和文件夹结果为:{}'.format(result))
        assert result == 1


        log.warning('移除代理策略，清空环境')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delftp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        log.warning('检查代理策略是否移除成功')
        fun.check_proxy_policy(dut='FrontDut', type='ftp', flag=False)

    def teardown_class(self):
        # 回收环境
        clr_env.iso_teardown_met('ftp', base_path)
        clr_env.iso_setup_class(dut='FrontDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')

