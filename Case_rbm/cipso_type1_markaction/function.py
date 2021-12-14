# encoding='utf-8'
'''
脚本一：
用例名称：验证含type1标记策略的是转换模式时的规则
编写人员：刘超
编写日期：2021/11/12
测试目的：验证含type1标记策略的是转换模式时的规则
测试步骤：
1.设备下发转换标记策略，通过babbitMQ下发
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文
3.服务端抓取并分析报文
4.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文成功
3.服务端抓取分析报文cat为0x1,0x0,0x0,0x0成功
4.设备移除策略成功，可以使用tupleacl --get查看

脚本二：
用例名称：验证含type1标记策略的是反向会话时的规则
编写人员：刘超
编写日期：2021/11/12
测试目的：验证含type1标记策略的是反向会话时的规则
测试步骤：
1.设备下发转换标记策略，通过babbitMQ下发
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文
3.客户端抓取并分析报文
4.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端tcpreplay发送cat为0x1,0x2,0x3,0x4的报文成功
3.客户端抓取分析报文cat为0x1,0x0,0x0,0x0成功
4.设备移除策略成功，可以使用tupleacl --get查看

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
    from Case_rbm.cipso_type1_markaction import index
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


class Test_cipso_type1_markaction():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env
        self.case1_mtLabel = index.case1_mtLabel
        self.case1_tgLabel = index.case1_tgLabel
        self.pkt1_cfg = index.pkt1_cfg

        self.case2_mtLabel = index.case2_mtLabel
        self.case2_rvTgLabel = index.case2_rvTgLabel
        self.pkt2_cfg = index.pkt2_cfg
        clr_env.clear_env()


    @allure.feature('用例一：验证含type1标记策略的是转换模式时的规则')
    def test_cipso_type1_change(self):
        log.warning('用例一：验证含type1标记策略的是转换模式时的规则')
        # 设备设置DOI为1
        # 客户端发送DOI为1的报文
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1 = self.pkt1_cfg["capture"][0], self.pkt1_cfg["capture"][1], self.pkt1_cfg["capture"][2], self.pkt1_cfg["capture"][3]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1= self.pkt1_cfg["send"][0], self.pkt1_cfg["send"][1], self.pkt1_cfg["send"][2]
        read_name1, read_id = self.pkt1_cfg["read"][0], self.pkt1_cfg["read"][1]
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case1_mtLabel,
                       tgLabel=self.case1_tgLabel)

        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt1_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case1_mtLabel)

    @allure.feature('用例二：验证含type1标记策略的是反向会话时的规则')
    def test_cipso_type1_rechange(self):
        log.warning('用例二：验证含type1标记策略的是反向会话时的规则')
        # 设备设置DOI为1
        # 客户端发送DOI为1的报文
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1 = self.pkt2_cfg["capture"][0], self.pkt2_cfg["capture"][1], self.pkt2_cfg["capture"][2], self.pkt2_cfg["capture"][3]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1= self.pkt2_cfg["send"][0], self.pkt2_cfg["send"][1], self.pkt2_cfg["send"][2]
        read_name1, read_id = self.pkt2_cfg["read"][0], self.pkt2_cfg["read"][1]
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case2_mtLabel,rvTgLabel=self.case2_rvTgLabel)

        # 客户端抓取报文
        fun.cmd(f"rm -rf /opt/pkt/{cap_pcap1}", 'c')
        pre_cfg1 = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap1)
        log.warning('客户端设置抓取报文：{}'.format(pre_cfg1))
        fun.cmd(pre_cfg1, 'c', thread=1)
        time.sleep(10)
        # 客户端发送报文
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap1)
        log.warning('客户端发送报文：{}'.format(send_cmd))
        fun.cmd(send_cmd, 'c')
        log.warning('step wait 20s')
        time.sleep(10)
        # 检查客户端报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 'c')
        fun.pid_kill(cap_pcap1)
        log.warning('客户端检查报文是否存在：{}'.format(pcap_file))
        assert cap_pcap1 in pcap_file
        # 客户端读取并分析报文
        read_cmd = fun.pkt_read(read_name1, read_id)
        read_re = fun.cmd(read_cmd, 'c')
        log.warning('客户端读取并分析报文：{}'.format(read_re))
        exp = self.pkt2_cfg["expect"][0]
        assert exp == read_re
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case2_mtLabel)


    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
