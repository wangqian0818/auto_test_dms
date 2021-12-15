'''
脚本一：
用例名称：验证隔离策略下基于一种MIME类型设置放行的网页访问策略
编写人员：李皖秋
编写日期：2021.7.9
测试目的：验证隔离策略下基于一种MIME类型设置放行的网页访问策略
测试步骤：
1、下发http的隔离策略：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来
2、下发http的MIME白名单，参数为：pdf，等待nginx的24个进程起来
3、控制台发送get请求，不包含请求内容
4、控制台发送get请求，请求内容不包含MIME白名单
5、控制台发送get请求，请求内容包含MIME白名单：pdf
6、移除http的隔离策略，清空环境，等待nginx的24个进程起来
7、移除网页访问策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/http.json文件应该包含：s_content_type和MIME白名单参数：pdf
3、请求成功，请求到的内容为server的index.html文件内包含的内容
4、请求失败，状态码返回为403
5、请求成功，状态码返回为200
6、cat /etc/jsac/http.stream应该不包含代理ip和port
7、cat /etc/jsac/http.json文件应该不包含：http协议

脚本二：
用例名称：验证隔离策略下基于多种MIME类型设置放行的网页访问策略
编写人员：李皖秋
编写日期：2021.7.9
测试目的：验证隔离策略下基于多种MIME类型设置放行的网页访问策略
测试步骤：
1、下发http的隔离策略：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来
2、下发http的MIME白名单，参数为：js、mps、gif、tsv、avi，等待nginx的24个进程起来
3、控制台发送get请求，不包含请求内容
4、控制台发送get请求，请求内容不包含MIME白名单
5、控制台发送get请求，请求内容包含MIME白名单：js
6、控制台发送get请求，请求内容包含MIME白名单：mps
7、控制台发送get请求，请求内容包含MIME白名单：gif
8、控制台发送get请求，请求内容包含MIME白名单：tsv
9、控制台发送get请求，请求内容包含MIME白名单：avi
10、移除http的隔离策略，清空环境，等待nginx的24个进程起来
11、移除网页访问策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/http.json文件应该包含：s_content_type和MIME白名单参数：js、mps、gif、tsv、avi
3、请求成功，请求到的内容为server的index.html文件内包含的内容
4、请求失败，状态码返回为403
5、请求成功，状态码返回为200
6、请求成功，状态码返回为200
7、请求成功，状态码返回为200
8、请求成功，状态码返回为200
9、请求成功，状态码返回为200
10、cat /etc/jsac/http.stream应该不包含代理ip和port
11、cat /etc/jsac/http.json文件应该不包含：http协议

脚本三：
用例名称：验证隔离策略下基于所有MIME类型设置放行的网页访问策略
编写人员：李皖秋
编写日期：2021.7.9
测试目的：验证隔离策略下基于所有MIME类型设置放行的网页访问策略
测试步骤：
1、下发http的隔离策略：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来
2、下发http的MIME白名单，参数为：所有MIME类型，等待nginx的24个进程起来
3、控制台发送get请求，不包含请求内容
4、控制台发送get请求，请求内容包含MIME白名单：doc
5、控制台发送get请求，请求内容包含MIME白名单：js
6、控制台发送get请求，请求内容包含MIME白名单：mps
7、控制台发送get请求，请求内容包含MIME白名单：gif
8、控制台发送get请求，请求内容包含MIME白名单：tsv
9、控制台发送get请求，请求内容包含MIME白名单：avi
10、移除http的隔离策略，清空环境，等待nginx的24个进程起来
11、移除网页访问策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/http.json文件应该包含：s_content_type和MIME所有类型
3、请求成功，请求到的内容为server的index.html文件内包含的内容
4、请求成功，状态码返回为200
5、请求成功，状态码返回为200
6、请求成功，状态码返回为200
7、请求成功，状态码返回为200
8、请求成功，状态码返回为200
9、请求成功，状态码返回为200
10、cat /etc/jsac/http.stream应该不包含代理ip和port
11、cat /etc/jsac/http.json文件应该不包含：http协议
'''
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
    from Case_rbm.iso_http_check_MIME_allow import index
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
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain

proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
http_url = index.http_url
http_content = baseinfo.http_content


class Test_iso_http_check_MIME_allow():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')

    def teardown_method(self):

        clr_env.iso_teardown_met('http', base_path)
        clr_env.clear_datacheck('http', base_path)

        clr_env.iso_setup_class(dut='FrontDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        self.case1_step1 = index.case1_step1
        self.case1_step11 = index.case1_step11
        self.case1_step2 = index.case1_step2
        self.case2_step2 = index.case2_step2
        self.case3_step2 = index.case3_step2
        self.delcheck = index.delcheck
        self.data = index.data
        self.case1_uri = index.case1_uri
        self.case2_uri1 = index.case2_uri1
        self.case2_uri2 = index.case2_uri2
        self.case2_uri3 = index.case2_uri3
        self.case2_uri4 = index.case2_uri4
        self.case2_uri5 = index.case2_uri5
        self.base_uri = index.base_uri

        self.check1_uri = index.check1_uri
        self.application_uri = index.application_uri
        self.audio_uri = index.audio_uri
        self.image_uri = index.image_uri
        self.text_uri = index.text_uri
        self.video_uri = index.video_uri

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于一种MIME类型设置放行的网页访问策略')
    def test_iso_http_check_MIME_allow_a1(self):

        # 下发配置
        log.warning('1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来;预期netstat -anp |grep tcp应该可以查看到监听ip和端口')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step11[key][1] in re

        # 数据检查
        log.warning('2、下发http的MIME白名单，参数为：pdf，等待nginx的24个进程起来;预期cat /etc/jsac/http.json文件应该包含：s_content_type和MIME白名单参数：pdf')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', mime_action=0, mime_data=self.check1_uri),
                 FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'FrontDut', self.case1_step2[key][1], '配置', 100)
            assert self.case1_step2[key][1] in re

        # 发送get请求，不指定内容的普通请求
        log.warning('3、控制台发送get请求，不包含请求内容;请求成功，请求到的内容为server的index.html文件内包含的内容')
        status_code = http_check.http_get(http_url, flag=1)
        log.warning('get普通请求的请求内容为：{}'.format(status_code))
        assert status_code == 200

        # 发送get请求，请求内容不包含MIME白名单
        log.warning('4、控制台发送get请求，请求内容不包含MIME白名单;请求失败，状态码返回为403')
        status_code = http_check.http_get(self.base_uri, self.data, flag=1)
        log.warning('get请求内容不包含MIME白名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 发送get请求，请求内容包含MIME白名单
        log.warning('5、控制台发送get请求，请求内容包含MIME白名单：pdf;请求成功，状态码返回为200')
        status_code = http_check.http_get(self.case1_uri, self.data, flag=1)
        log.warning('get请求内容包含MIM第一个E白名单返回的状态码为：{}'.format(status_code))
        assert status_code == 200

        # 移除策略，还原环境
        log.warning('6、移除代理策略，清空环境，等待nginx的24个进程起来;cat /etc/jsac/http.stream应该不包含代理ip和port')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100, flag='不存在')
            log.warning(re)
            assert self.case1_step1[key][1] not in re

        # 检查网页访问策略是否清空
        log.warning('7、移除网页访问策略，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该不包含：http协议')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1
        for key in self.delcheck:
            re = fun.wait_data(self.delcheck[key][0], 'FrontDut', self.delcheck[key][1], '配置', 100, flag='不存在')
            assert self.delcheck[key][1] not in re

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于多种MIME类型设置放行的网页访问策略')
    def test_iso_http_check_MIME_allow_a2(self):

        # 下发配置
        log.warning('1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来;预期netstat -anp |grep tcp应该可以查看到监听ip和端口')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step11[key][1] in re

        # 数据检查
        log.warning(
            '2、下发http的MIME白名单，参数为：js、mps、gif、tsv、avi，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该包含：s_content_type和MIME白名单参数：pdf')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', mime_action=0,
                                            mime_data=f"{self.application_uri};{self.audio_uri};{self.image_uri};{self.text_uri};{self.video_uri}"),
                 FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1
        for key in self.case2_step2:
            re = fun.wait_data(self.case2_step2[key][0], 'FrontDut', self.case2_step2[key][1], '配置', 100)
            log.warning(re)
            assert self.case2_step2[key][1] in re

        # 发送get请求，不指定内容的普通请求
        log.warning('3、控制台发送get请求，不包含请求内容;请求成功，请求到的内容为server的index.html文件内包含的内容')
        status_code = http_check.http_get(http_url, flag=1)
        log.warning('get普通请求的请求内容为：{}'.format(status_code))
        assert status_code == 200

        # 发送get请求，请求内容不包含MIME白名单
        log.warning('4、控制台发送get请求，请求内容不包含MIME白名单;请求失败，状态码返回为403')
        status_code = http_check.http_get(self.base_uri, self.data, flag=1)
        log.warning('get请求内容不包含MIME白名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 发送get请求，请求内容包含MIME第一个白名单
        log.warning('5、控制台发送get请求，请求内容包含MIME白名单：js;请求成功，状态码返回为200')
        status_code1 = http_check.http_get(self.case2_uri1, self.data, flag=1)
        log.warning('get请求内容包含MIM第一个白名单{}返回的状态码为：{}'.format(self.case2_uri1, status_code1))
        assert status_code1 == 200

        # 发送get请求，请求内容包含MIME第二个白名单
        log.warning('6、控制台发送get请求，请求内容包含MIME白名单：mps;请求成功，状态码返回为200')
        status_code2 = http_check.http_get(self.case2_uri2, self.data, flag=1)
        log.warning('get请求内容包含MIM第二个白名单{}返回的状态码为：{}'.format(self.case2_uri2, status_code2))
        assert status_code2 == 200

        # 发送get请求，请求内容包含MIME第三个白名单
        log.warning('7、控制台发送get请求，请求内容包含MIME白名单：gif;请求成功，状态码返回为200')
        status_code3 = http_check.http_get(self.case2_uri3, self.data, flag=1)
        log.warning('get请求内容包含MIM第三个白名单{}返回的状态码为：{}'.format(self.case2_uri3, status_code3))
        assert status_code3 == 200

        # 发送get请求，请求内容包含MIME第四个白名单
        log.warning('8、控制台发送get请求，请求内容包含MIME白名单：tsv;请求成功，状态码返回为200')
        status_code4 = http_check.http_get(self.case2_uri4, self.data, flag=1)
        log.warning('get请求内容包含MIM第四个白名单{}返回的状态码为：{}'.format(self.case2_uri4, status_code4))
        assert status_code4 == 200

        # 发送get请求，请求内容包含MIME第五个白名单
        log.warning('9、控制台发送get请求，请求内容包含MIME白名单：avi;请求成功，状态码返回为200')
        status_code5 = http_check.http_get(self.case2_uri5, self.data, flag=1)
        log.warning('get请求内容包含MIM第五个白名单{}返回的状态码为：{}'.format(self.case2_uri5, status_code5))
        assert status_code5 == 200

        # 移除策略，还原环境
        log.warning('10、移除代理策略，清空环境，等待nginx的24个进程起来;cat /etc/jsac/http.stream应该不包含代理ip和port')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100, flag='不存在')
            log.warning(re)
            assert self.case1_step1[key][1] not in re

        # 检查网页访问策略是否清空
        log.warning('11、移除网页访问策略，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该不包含：http协议')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1
        for key in self.delcheck:
            re = fun.wait_data(self.delcheck[key][0], 'FrontDut', self.delcheck[key][1], '配置', 100, flag='不存在')
            assert self.delcheck[key][1] not in re

    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于所有MIME类型设置放行的网页访问策略')
    def test_iso_http_check_MIME_allow_a3(self):
        # 下发配置
        log.warning(
            '1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来;预期cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='addhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            log.warning(re)
            assert self.case1_step11[key][1] in re

        # 数据检查
        log.warning('2、下发http的MIME白名单，参数为：所有MIME类型，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该包含：s_content_type和MIME所有类型')
        data = "evy;fif;spl;hta;acx;hqx;doc;dot;*;bin;class;dms;exe;lha;lzh;oda;axs;pdf;prf;p10;crl;ai;eps;ps;rtf;" \
               "setpay;setreg;xla;xlc;xlm;xls;xlt;xlw;msg;sst;cat;stl;pot;pps;ppt;mpp;wcm;wdb;wks;wps;hlp;bcpio;cdf;" \
               "application/x-compress;z;cpio;csh;dcr;dir;dxr;dvi;gtar;gz;hdf;ins;isp;iii;js;latex;mdb;crd;clp;dll;" \
               "m13;m14;mvb;wmf;mny;pub;scd;trm;wri;cdf;nc;pma;pmc;pml;pmr;pmw;p12;pfx;p7b;spc;p7r;p7c;p7m;p7s;sh;" \
               "shar;swf;sit;sv4cpio;sv4crc;tar;tcl;tex;texi;texinfo;roff;t;tr;man;me;ms;ustar;src;cer;crt;der;pko;" \
               "zip;au;snd;mid;rmi;mps;aif;aifc;aiff;m3u;ra;ram;wav;bmp;cod;gif;ief;jpe;jpeg;jpg;jfif;svg;tif;tiff;" \
               "ras;cmx;ico;pnm;pbm;pgm;ppm;rgb;xbm;xpm;xwd;mht;mhtml;mws;css;323;htm;html;stm;uls;bas;c;h;txt;rtx;" \
               "sct;tsv;htt;htc;etx;vcf;mp2;mpa;mpe;mpeg;mpg;mpv2;mov;qt;lsf;lsx;asf;asr;asx;avi;movie;flr;vrml;wrl;" \
               "wrz;xaf;xof"
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='httpcheck', mime_action=0, mime_data=data), FrontDomain,
                 base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1
        for key in self.case3_step2:
            re = fun.wait_data(self.case3_step2[key][0], 'FrontDut', self.case3_step2[key][1], '配置', 100)
            log.warning(re)
            assert self.case3_step2[key][1] in re
        MIME_res = fun.cmd(r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local", 'FrontDut')
        log.warning('查看MIME白名单为：{}'.format(MIME_res))

        # 发送get请求，不指定内容的普通请求
        log.warning('3、控制台发送get请求，不包含请求内容;请求成功，请求到的内容为server的index.html文件内包含的内容')
        status_code = http_check.http_get(http_url, flag=1)
        log.warning('get普通请求的请求内容为：{}'.format(status_code))
        assert status_code == 200

        # 发送get请求，请求内容包含MIME白名单
        log.warning('4、控制台发送get请求，请求内容包含MIME白名单：doc;请求成功，状态码返回为200')
        status_code = http_check.http_get(self.base_uri, self.data, flag=1)
        log.warning('get请求内容包含MIME白名单返回的状态码为：{}'.format(status_code))
        assert status_code == 200

        # 发送get请求，请求内容包含MIME第一个白名单
        log.warning('5、控制台发送get请求，请求内容包含MIME白名单：js;请求成功，状态码返回为200')
        status_code1 = http_check.http_get(self.case2_uri1, self.data, flag=1)
        log.warning('get请求内容包含MIM第一个白名单{}返回的状态码为：{}'.format(self.case2_uri1, status_code1))
        assert status_code1 == 200

        # 发送get请求，请求内容包含MIME第二个白名单
        log.warning('6、控制台发送get请求，请求内容包含MIME白名单：mps;请求成功，状态码返回为200')
        status_code2 = http_check.http_get(self.case2_uri2, self.data, flag=1)
        log.warning('get请求内容包含MIM第二个白名单{}返回的状态码为：{}'.format(self.case2_uri2, status_code2))
        assert status_code2 == 200

        # 发送get请求，请求内容包含MIME第三个白名单
        log.warning('7、控制台发送get请求，请求内容包含MIME白名单：gif;请求成功，状态码返回为200')
        status_code3 = http_check.http_get(self.case2_uri3, self.data, flag=1)
        log.warning('get请求内容包含MIM第三个白名单{}返回的状态码为：{}'.format(self.case2_uri3, status_code3))
        assert status_code3 == 200

        # 发送get请求，请求内容包含MIME第四个白名单
        log.warning('8、控制台发送get请求，请求内容包含MIME白名单：tsv;请求成功，状态码返回为200')
        status_code4 = http_check.http_get(self.case2_uri4, self.data, flag=1)
        log.warning('get请求内容包含MIM第四个白名单{}返回的状态码为：{}'.format(self.case2_uri4, status_code4))
        assert status_code4 == 200

        # 发送get请求，请求内容包含MIME第五个白名单
        log.warning('9、控制台发送get请求，请求内容包含MIME白名单：avi;请求成功，状态码返回为200')
        status_code5 = http_check.http_get(self.case2_uri5, self.data, flag=1)
        log.warning('get请求内容包含MIM第五个白名单{}返回的状态码为：{}'.format(self.case2_uri5, status_code5))
        assert status_code5 == 200

        # 移除策略，还原环境
        log.warning('10、移除代理策略，清空环境，等待nginx的24个进程起来;netstat -anp |grep tcp应该查看不到监听ip和端口')
        fun.send(rbmExc, tool.interface().setAccessconf(prototype='delhttp_front'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100, flag='不存在')
            log.warning(re)
            assert self.case1_step1[key][1] not in re

        # 检查网页访问策略是否清空
        log.warning('11、移除网页访问策略，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该不包含：http协议')
        fun.send(rbmExc, tool.interface().app_safe_policy(prototype='delhttpcheck'), FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1
        for key in self.delcheck:
            re = fun.wait_data(self.delcheck[key][0], 'FrontDut', self.delcheck[key][1], '配置', 100, flag='不存在')
            assert self.delcheck[key][1] not in re

    def teardown_class(self):
        # 回收环境
        clr_env.iso_setup_class(dut='FrontDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')

