# encoding='utf-8'
'''
脚本一：
用例名称：验证含type1标记策略的类别在子集比对方式下的规则
编写人员：刘超
编写日期：2021/11/12
测试目的：验证含type1标记策略的类别在子集比对方式下的规则
测试步骤：
1.设备通过babbitMQ下发Match(对比方式)为0、cat为0x3,0x2,0x3,0x4的标记策略
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文
3.服务端抓取并分析报文
4.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文成功
3.服务端抓取分析成功
4.设备移除策略成功，使用tupleacl --get查询不到此策略说明删除成功

脚本二：
用例名称：验证含type1标记策略的类别在交集比对方式下的规则
编写人员：刘超
编写日期：2021/11/12
测试目的：验证含type1标记策略的类别在交集比对方式下的规则
测试步骤：
1.设备下发Match为1、cat为0xa,0x2,0x7,0x9的标记策略，通过babbitMQ下发
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文
3.服务端抓取并分析报文
4.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文成功
3.服务端抓取分析成功
4.设备移除策略成功，使用tupleacl --get查询不到此策略说明删除成功

脚本三：
用例名称：验证含type1标记策略的类别在非比对方式下的规则
编写人员：刘超
编写日期：2021/11/12
测试目的：验证含type1标记策略的类别在非比对方式下的规则
测试步骤：
1.设备下发Match为3、cat为0x2,0x0,0x0,0x1的标记策略，通过babbitMQ下发
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文
3.服务端抓取并分析报文
4.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文成功
3.服务端抓取分析成功
4.设备移除策略成功，使用tupleacl --get查询不到此策略说明删除成功

脚本四：
用例名称：验证含type1标记策略的类别在等于对方式下的规则
编写人员：刘超
编写日期：2021/11/12
测试目的：验证含type1标记策略的类别在等于对方式下的规则
测试步骤：
1.设备下发Match为2、cat为0x1,0x2,0x3,0x4的标记策略，通过babbitMQ下发
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文
3.服务端抓取并分析报文
4.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文成功
3.服务端抓取分析成功
4.设备移除策略成功，使用tupleacl --get查询不到此策略说明删除成功

脚本五：
用例名称：验证type1类型下的类别左边界（最小）值
编写人员：刘超
编写日期：2021/11/12
测试目的：验证type1类型下的类别左边界（最小）值
测试步骤：
1.设备下发cat为0x0,0x0,0x0,0x0的标记策略，通过babbitMQ下发
2.客户端tcpreplay发送cat为0x0,0x0,0x0,0x0的报文
3.服务端抓取并分析报文
4.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端tcpreplay发送cat为0x0,0x0,0x0,0x0的报文成功
3.服务端抓取分析成功
4.设备移除策略成功，使用tupleacl --get查询不到此策略说明删除成功

脚本六：
用例名称：验证type1类型下的类别右边界（最大）值
编写人员：刘超
编写日期：2021/11/12
测试目的：验证type1类型下的类别右边界（最大）值
测试步骤：
1.设备下发cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的标记策略，通过babbitMQ下发
2.客户端tcpreplay发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文
3.服务端抓取并分析报文
4.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端tcpreplay发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文成功
3.服务端抓取分析成功
4.设备移除策略成功，使用tupleacl --get查询不到此策略说明删除成功

'''

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
    from Case_rbm.cipso_type1_cat import index
    from common import fun, tool
    import common.ssh as c_ssh
except Exception as err:
    log.warning(
        '导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误

from common import baseinfo
from common import clr_env
from common.rabbitmq import *

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc

gwClientIp = baseinfo.gwClientIp
clientOpeIp = baseinfo.clientOpeIp
serverOpeIp = baseinfo.serverOpeIp


class Test_cipso_type1_cat():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.case1_mtLabel = index.case1_mtLabel
        self.case2_mtLabel = index.case2_mtLabel
        self.case3_mtLabel = index.case3_mtLabel
        self.case4_mtLabel = index.case4_mtLabel
        self.case5_mtLabel = index.case5_mtLabel
        self.case5_tgLabel = index.case5_tgLabel
        self.case6_mtLabel = index.case6_mtLabel
        self.case6_tgLabel = index.case6_tgLabel
        self.pkt1_cfg = index.pkt1_cfg
        self.pkt2_cfg = index.pkt2_cfg
        self.pkt3_cfg = index.pkt3_cfg
        self.pkt4_cfg = index.pkt4_cfg
        self.pkt5_cfg = index.pkt5_cfg
        self.pkt6_cfg = index.pkt6_cfg
        self.case7_mtLabel = index.case7_mtLabel
        self.case7_tgLabel = index.case7_tgLabel
        self.pkt7_cfg = index.pkt7_cfg
        self.case8_mtLabel = index.case8_mtLabel
        self.case8_tgLabel = index.case8_tgLabel
        self.pkt8_cfg = index.pkt8_cfg
        self.case9_mtLabel = index.case9_mtLabel
        self.case9_tgLabel = index.case9_tgLabel
        self.pkt9_cfg = index.pkt9_cfg
        self.case10_mtLabel = index.case10_mtLabel
        self.case10_tgLabel = index.case10_tgLabel
        self.pkt10_cfg = index.pkt10_cfg
        self.case11_mtLabel = index.case11_mtLabel
        self.case11_tgLabel = index.case11_tgLabel
        self.pkt11_cfg = index.pkt11_cfg
        self.case12_mtLabel = index.case12_mtLabel
        self.case12_tgLabel = index.case12_tgLabel
        self.pkt12_cfg = index.pkt12_cfg
        self.clr_env = clr_env
        clr_env.clear_env()


    @allure.feature('用例一：验证含type1标记策略的类别在子集比对方式下的规则')
    def test_cipso_type1_cat_inc(self):
        log.warning('用例一：验证含type1标记策略的类别在子集比对方式下的规则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1 = self.pkt1_cfg["capture"][0], self.pkt1_cfg["capture"][1], \
                                                    self.pkt1_cfg["capture"][2], self.pkt1_cfg["capture"][3]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1 = self.pkt1_cfg["send"][0], self.pkt1_cfg["send"][1], self.pkt1_cfg["send"][2]
        read_name1, read_id = self.pkt1_cfg["read"][0], self.pkt1_cfg["read"][1]

        # 下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case1_mtLabel)

        log.warning('验证客户端发送cat为0x1,0x2,0x3,0x4的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt1_cfg["expect"][0])

        # 删除标记策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case1_mtLabel)


    @allure.feature('用例二：验证含type1标记策略的类别在交集比对方式下的规则')
    def test_cipso_type1_cat_1bit(self):
        log.warning('用例二：验证含type1标记策略的类别在交集比对方式下的规则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1 = self.pkt2_cfg["capture"][0], self.pkt2_cfg["capture"][1], \
                                                    self.pkt2_cfg["capture"][2], self.pkt2_cfg["capture"][3]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1 = self.pkt2_cfg["send"][0], self.pkt2_cfg["send"][1], self.pkt2_cfg["send"][2]
        read_name1, read_id = self.pkt2_cfg["read"][0], self.pkt2_cfg["read"][1]
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case2_mtLabel)
        log.warning('验证客户端发送cat为0x1,0x2,0x3,0x4的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt2_cfg["expect"][0])
        # 删除标记策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case2_mtLabel)


    @allure.feature('用例三：验证含type1标记策略的类别在非比对方式下的规则')
    def test_cipso_type1_cat_neq(self):
        log.warning('用例三：验证含type1标记策略的类别在非比对方式下的规则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1 = self.pkt3_cfg["capture"][0], self.pkt3_cfg["capture"][1], \
                                                    self.pkt3_cfg["capture"][2], self.pkt3_cfg["capture"][3]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1 = self.pkt3_cfg["send"][0], self.pkt3_cfg["send"][1], self.pkt3_cfg["send"][2]
        read_name1, read_id = self.pkt3_cfg["read"][0], self.pkt3_cfg["read"][1]
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case3_mtLabel)

        log.warning('验证客户端发送cat为0x1,0x2,0x3,0x4的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt3_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case3_mtLabel)


    @allure.feature('用例四：验证含type1标记策略的类别在等于比对方式下的规则')
    def test_cipso_type1_cat_eq(self):
        log.warning('用例四：验证含type1标记策略的类别在等于比对方式下的规则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1 = self.pkt4_cfg["capture"][0], self.pkt4_cfg["capture"][1], \
                                                    self.pkt4_cfg["capture"][2], self.pkt4_cfg["capture"][3]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1 = self.pkt4_cfg["send"][0], self.pkt4_cfg["send"][1], self.pkt4_cfg["send"][2]
        read_name1, read_id = self.pkt4_cfg["read"][0], self.pkt4_cfg["read"][1]
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case4_mtLabel)

        log.warning('验证客户端发送cat为0x1,0x2,0x3,0x4的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt4_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case4_mtLabel)

    @allure.feature('用例五：验证type1类型下的类别左边界（最小）值（加标和去标都测）')
    def test_cipso_type1_cat_minimum(self):
        log.warning('用例五：验证type1类型下的类别左边界（最小）值')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2 = self.pkt5_cfg["capture"][0], self.pkt5_cfg["capture"][1], \
                                                    self.pkt5_cfg["capture"][2], self.pkt5_cfg["capture"][3], self.pkt5_cfg["capture"][4]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2 = self.pkt5_cfg["send"][0], self.pkt5_cfg["send"][1], self.pkt5_cfg["send"][2], self.pkt5_cfg["send"][3]
        read_name1, read_name2, read_id = self.pkt5_cfg["read"][0], self.pkt5_cfg["read"][1], self.pkt5_cfg["read"][2]
        # 1.---------------------------测试去标---------------------------------
        log.warning('去标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case5_mtLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0x0,0x0,0x0,0x0的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt5_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case5_mtLabel)
        # 2.---------------------------测试加标---------------------------------
        log.warning('加标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case5_mtLabel, tgLabel=self.case5_tgLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0x0,0x0,0x0,0x0的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap2, c_iface, c_num, c_pcap2, read_name2,
                                   read_id, self.pkt5_cfg["expect"][1])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case5_mtLabel)

    @allure.feature('用例六：验证type1类型下的类别右边界（最大）值')
    def test_cipso_type1_cat_maximum(self):
        log.warning('用例六：验证type1类型下的类别右边界（最大）值')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2 = self.pkt6_cfg["capture"][0], self.pkt6_cfg["capture"][1], \
                                                    self.pkt6_cfg["capture"][2], self.pkt6_cfg["capture"][3], self.pkt6_cfg["capture"][4]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2 = self.pkt6_cfg["send"][0], self.pkt6_cfg["send"][1], self.pkt6_cfg["send"][2], self.pkt6_cfg["send"][3]
        read_name1, read_name2, read_id = self.pkt6_cfg["read"][0], self.pkt6_cfg["read"][1], self.pkt6_cfg["read"][2]
        # 1.---------------------------测试去标---------------------------------
        log.warning('去标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case6_mtLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt6_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case6_mtLabel)
        # 2.---------------------------测试加标---------------------------------
        log.warning('加标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case6_mtLabel, tgLabel=self.case6_tgLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap2, c_iface, c_num, c_pcap2, read_name2,
                                   read_id, self.pkt6_cfg["expect"][1])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case6_mtLabel)

    @allure.feature('用例七：验证type1类型下的类别为f000时，对报文的处理原则')
    def test_cipso_type1_cat_f000(self):
        log.warning('用例七：验证type1类型下的类别为f000时，对报文的处理原则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2 = self.pkt7_cfg["capture"][0], self.pkt7_cfg["capture"][1], \
                                                    self.pkt7_cfg["capture"][2], self.pkt7_cfg["capture"][3], self.pkt7_cfg["capture"][4]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2 = self.pkt7_cfg["send"][0], self.pkt7_cfg["send"][1], self.pkt7_cfg["send"][2], self.pkt7_cfg["send"][3]
        read_name1, read_name2, read_id = self.pkt7_cfg["read"][0], self.pkt7_cfg["read"][1], self.pkt7_cfg["read"][2]
        # 1.---------------------------测试去标---------------------------------
        log.warning('去标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case7_mtLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt7_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case7_mtLabel)
        # 2.---------------------------测试加标---------------------------------
        log.warning('加标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case7_mtLabel, tgLabel=self.case7_tgLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap2, c_iface, c_num, c_pcap2, read_name2,
                                   read_id, self.pkt7_cfg["expect"][1])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case7_mtLabel)

    @allure.feature('用例八：验证type1类型下的类别为ff00时，对报文的处理原则')
    def test_cipso_type1_cat_ff00(self):
        log.warning('用例八：验证type1类型下的类别为ff00时，对报文的处理原则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2 = self.pkt8_cfg["capture"][0], \
                                                               self.pkt8_cfg["capture"][1], \
                                                               self.pkt8_cfg["capture"][2], \
                                                               self.pkt8_cfg["capture"][3], \
                                                               self.pkt8_cfg["capture"][4]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2 = self.pkt8_cfg["send"][0], self.pkt8_cfg["send"][1], \
                                           self.pkt8_cfg["send"][2], self.pkt8_cfg["send"][3]
        read_name1, read_name2, read_id = self.pkt8_cfg["read"][0], self.pkt8_cfg["read"][1], self.pkt8_cfg["read"][
            2]
        # 1.---------------------------测试去标---------------------------------
        log.warning('去标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case8_mtLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt8_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case8_mtLabel)
        # 2.---------------------------测试加标---------------------------------
        log.warning('加标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case8_mtLabel,
                       tgLabel=self.case8_tgLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap2, c_iface, c_num, c_pcap2, read_name2,
                                   read_id, self.pkt8_cfg["expect"][1])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case8_mtLabel)

    @allure.feature('用例九：验证type1类型下的类别为fff0时，对报文的处理原则')
    def test_cipso_type1_cat_fff0(self):
        log.warning('用例九：验证type1类型下的类别为fff0时，对报文的处理原则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2 = self.pkt9_cfg["capture"][0], \
                                                               self.pkt9_cfg["capture"][1], \
                                                               self.pkt9_cfg["capture"][2], \
                                                               self.pkt9_cfg["capture"][3], \
                                                               self.pkt9_cfg["capture"][4]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2 = self.pkt9_cfg["send"][0], self.pkt9_cfg["send"][1], \
                                           self.pkt9_cfg["send"][2], self.pkt9_cfg["send"][3]
        read_name1, read_name2, read_id = self.pkt9_cfg["read"][0], self.pkt9_cfg["read"][1], self.pkt9_cfg["read"][
            2]
        # 1.---------------------------测试去标---------------------------------
        log.warning('去标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case9_mtLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt9_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case9_mtLabel)
        # 2.---------------------------测试加标---------------------------------
        log.warning('加标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case9_mtLabel,
                       tgLabel=self.case9_tgLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap2, c_iface, c_num, c_pcap2, read_name2,
                                   read_id, self.pkt9_cfg["expect"][1])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case9_mtLabel)

    @allure.feature('用例十：验证type1类型下的类别为0fff时，对报文的处理原则')
    def test_cipso_type1_cat_0fff(self):
        log.warning('用例十：验证type1类型下的类别为0fff时，对报文的处理原则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2 = self.pkt10_cfg["capture"][0], \
                                                               self.pkt10_cfg["capture"][1], \
                                                               self.pkt10_cfg["capture"][2], \
                                                               self.pkt10_cfg["capture"][3], \
                                                               self.pkt10_cfg["capture"][4]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2 = self.pkt10_cfg["send"][0], self.pkt10_cfg["send"][1], \
                                           self.pkt10_cfg["send"][2], self.pkt10_cfg["send"][3]
        read_name1, read_name2, read_id = self.pkt10_cfg["read"][0], self.pkt10_cfg["read"][1], self.pkt10_cfg["read"][2]
        # 1.---------------------------测试去标---------------------------------
        log.warning('去标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case10_mtLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt10_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case10_mtLabel)
        # 2.---------------------------测试加标---------------------------------
        log.warning('加标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case10_mtLabel,
                       tgLabel=self.case10_tgLabel)
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap2, c_iface, c_num, c_pcap2, read_name2,
                                   read_id, self.pkt10_cfg["expect"][1])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case10_mtLabel)

    @allure.feature('用例十一：验证type1类型下的类别为f0ff时，对报文的处理原则')
    def test_cipso_type1_cat_f0ff(self):
        log.warning('用例十一：验证type1类型下的类别为f0ff时，对报文的处理原则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2 = self.pkt11_cfg["capture"][0], \
                                                               self.pkt11_cfg["capture"][1], \
                                                               self.pkt11_cfg["capture"][2], \
                                                               self.pkt11_cfg["capture"][3], \
                                                               self.pkt11_cfg["capture"][4]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2 = self.pkt11_cfg["send"][0], self.pkt11_cfg["send"][1], \
                                           self.pkt11_cfg["send"][2], self.pkt11_cfg["send"][3]
        read_name1, read_name2, read_id = self.pkt11_cfg["read"][0], self.pkt11_cfg["read"][1], self.pkt11_cfg["read"][2]
        # 1.---------------------------测试去标---------------------------------
        log.warning('去标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case11_mtLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt11_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case11_mtLabel)
        # 2.---------------------------测试加标---------------------------------
        log.warning('加标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case11_mtLabel,
                       tgLabel=self.case11_tgLabel)
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap2, c_iface, c_num, c_pcap2, read_name2,
                                   read_id, self.pkt11_cfg["expect"][1])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case11_mtLabel)

    @allure.feature('用例十二：验证type1类型下的类别为ff0f时，对报文的处理原则')
    def test_cipso_type1_cat_ff0f(self):
        log.warning('用例十二：验证type1类型下的类别为ff0f时，对报文的处理原则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2 = self.pkt12_cfg["capture"][0], \
                                                               self.pkt12_cfg["capture"][1], \
                                                               self.pkt12_cfg["capture"][2], \
                                                               self.pkt12_cfg["capture"][3], \
                                                               self.pkt12_cfg["capture"][4]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2 = self.pkt12_cfg["send"][0], self.pkt12_cfg["send"][1], \
                                           self.pkt12_cfg["send"][2], self.pkt12_cfg["send"][3]
        read_name1, read_name2, read_id = self.pkt12_cfg["read"][0], self.pkt12_cfg["read"][1], self.pkt12_cfg["read"][2]
        # 1.---------------------------测试去标---------------------------------
        log.warning('去标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case12_mtLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt12_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case12_mtLabel)
        # 2.---------------------------测试加标---------------------------------
        log.warning('加标测试')
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case12_mtLabel,
                       tgLabel=self.case12_tgLabel)
        log.warning('验证客户端发送cat为0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap2, c_iface, c_num, c_pcap2, read_name2,
                                   read_id, self.pkt12_cfg["expect"][1])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case12_mtLabel)

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
