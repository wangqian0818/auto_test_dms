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
    from Case_rbm.iso_http_basic import index
    from common import fun, tool, clr_env
    import common.ssh as c_ssh
except Exception as err:
    log.warning(
        '导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误

from common import baseinfo
from common.rabbitmq import *
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain

proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
http_url = index.http_url
http_content = baseinfo.http_content


class Test_iso_http_basic():

    # def setup_method(self):
    #     clr_env.data_check_setup_met(dut='FrontDut')
    #
    # def teardown_method(self):
    #     clr_env.iso_setup_class(dut='FrontDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        fun.ssh_BG8010Server.connect()
        fun.ssh_BG8010Client.connect()
        fun.ssh_httpServer.connect()
        self.http_url = index.http_url
        self.downfile_url = index.downfile_url
        self.downlocalPath = index.downlocalPath
        self.upfile_url = index.upfile_url
        self.upfilename = index.upfilename
        self.uplocalPath = index.uplocalPath
        self.upMIME_type = index.upMIME_type
        self.up_url = index.up_url

        clr_env.iso_setup_class(dut='FrontDut')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的http代理策略')
    def test_iso_http_basic_a1(self):
        # # 下发配置
        # fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        # fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        # front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        # assert front_res == 1
        # # 检查代理策略是否下发成功
        # fun.check_proxy_policy(dut='FrontDut')

        # 发送get请求，验证隔离下的http策略
        log.warning('请求地址为{}'.format(self.http_url))
        status_code = http_check.http_get(self.http_url, flag=1)
        log.warning('检查内容为：{}'.format(http_content))
        log.warning('验证隔离下的http策略请求内容为：{}'.format(status_code))
        assert status_code == 200

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', flag=False)

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的http策略下载一个10M大小的文件')
    def test_iso_http_basic_a2(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut')

        # 发送get请求，验证get请求是否正常
        log.warning('请求地址为{}'.format(http_url))
        status_code = http_check.http_get(http_url)
        log.warning('验证隔离下的get请求内容为：{}'.format(status_code))

        # 发送get请求，验证隔离下的http策略下载一个10M大小的文件
        log.warning('下载的服务器地址为{}'.format(self.downfile_url))
        result = http_check.http_download(self.downfile_url, self.downlocalPath)
        assert result == 1

        # 判断文件大小是否是10M
        file_size = os.path.getsize(self.downlocalPath)
        file_size = file_size / float(1024 * 1024)  # 将单位转化为M
        log.warning('file_size: ', file_size)
        assert 9.5 <= file_size <= 10.5

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否移除成功
        fun.check_proxy_policy(dut='FrontDut', flag=False)

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的http策略上传一个10M大小的文件')
    def test_iso_http_basic_a3(self):
        # 下发配置
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front_post'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='http_post')

        # 初始化，检查server端无post.txt文件
        post_file = fun.search('/home/lwq', 'txt', 'BG8010Server')
        log.warning(post_file)
        if 'post.txt' in post_file:
            fun.cmd('rm -f /home/lwq/post.txt ', 'BG8010Server')

        # 服务器端开启post上传服务
        fun.cmd('cd /home/lwq && python3 Server.py', 'httpServer', thread=1)

        # 发送post请求，验证post请求是否正常
        log.warning('请求地址为{}'.format(self.up_url))
        status_code = http_check.http_post(self.up_url)
        log.warning('post普通请求的请求内容为：{}'.format(status_code))

        # 发送post请求，验证隔离下的http策略上传一个10M大小的文件
        log.warning('上传的服务器地址为{}'.format(self.upfile_url))
        result = http_check.http_upload(self.upfile_url, self.upfilename, self.uplocalPath, self.upMIME_type)
        assert result == 1

        # 检查文件是否生成
        post_file = fun.search('/home/lwq', 'txt', 'httpServer')
        log.warning('检查/home/lwq/目录下所有以txt结尾的文件列表为：{}'.format(post_file))
        assert 'post.txt' in post_file

        # 移除策略，清空环境
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front_post'), FrontDomain, base_path)
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查代理策略是否下发成功
        fun.check_proxy_policy(dut='FrontDut', type='http_post', flag=False)

    # def teardown_class(self):
    #     # 回收环境
    #     clr_env.iso_teardown_met('http', base_path)
    #     clr_env.iso_teardown_met('http_post', base_path)
    #     clr_env.iso_setup_class(dut='FrontDut')
    #     clr_env.iso_setup_class(dut='BackDut')
    #
    #     fun.rbm_close()
    #     fun.ssh_close('FrontDut')
    #
