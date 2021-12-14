# encoding='utf-8'
'''
脚本一：
用例名称：验证含type7标记策略的机密性和完整性都填的规则
编写人员：刘超
编写日期：2021/11/12
测试目的：验证含type7标记策略的机密性和完整性都填的规则
测试步骤：
1.设备下发“机密性等级10、完整性等级13”的标记策略，通过babbitMQ下发
2.客户端tcpreplay发送“机密性等级10、完整性等级13”的报文
3.服务端抓取并分析报文
4.客户端tcpreplay发送“机密性等级15、完整性等级13”的报文
5.服务端抓取并分析报文
6.客户端tcpreplay发送“机密性等级10、完整性等级12”的报文
7.服务端抓取并分析报文
8.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端发报文成功
3.服务端抓取分析成功
4.客户端发报文成功
5.服务端抓取不到报文
6.客户端发报文成功
7.服务端抓取不到报文
8.设备移除策略成功，可以使用tupleacl --get查看

脚本二：
用例名称：验证含type7标记策略的只填机密性（BLP模型）规则
编写人员：刘超
编写日期：2021/11/12
测试目的：验证含type7标记策略的只填机密性（BLP模型）规则
测试步骤：
1.设备下发“机密性等级13-15”的标记策略，通过babbitMQ下发
2.客户端tcpreplay发送“机密性等级13”的报文
3.服务端抓取并分析报文
4.客户端tcpreplay发送“机密性等级10”的报文
5.服务端抓取并分析报文
8.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端发报文成功
3.服务端抓取分析成功
4.客户端发报文成功
5.服务端抓取不到报文
6.设备移除策略成功，可以使用tupleacl --get查看

脚本三：
用例名称：验证含type7标记策略的只填完整性（BIBA模型）规则
编写人员：刘超
编写日期：2021/11/12
测试目的：验证含type7标记策略的只填完整性（BIBA模型）规则
测试步骤：
1.设备下发“机密性等级13-14”的标记策略，通过babbitMQ下发
2.客户端tcpreplay发送“完整性等级13”的报文
3.服务端抓取并分析报文
4.客户端tcpreplay发送“完整性等级15”的报文
5.服务端抓取并分析报文
6.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端发报文成功
3.服务端抓取分析成功
4.客户端发报文成功
5.服务端抓取报文失败
6.设备移除策略成功，可以使用tupleacl --get查看

脚本四：
用例名称：验证type7类型下的机密性和完整性密级的左边界（最小值）
编写人员：刘超
编写日期：2021/11/12
测试目的：验证type7类型下的机密性和完整性密级的左边界（最小值）
测试步骤：
1.设备下发“完整性为1、机密性为1”的标记策略，通过babbitMQ下发
2.客户端tcpreplay发送“完整性为1、机密性为1”的报文
3.服务端抓取并分析报文
4.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端发送报文成功
3.服务端抓取分析成功
4.设备移除策略成功，可以使用tupleacl --get查看

脚本五：
用例名称：验证type7类型下的机密性和完整性密级的右边界（最大值）
编写人员：刘超
编写日期：2021/11/12
测试目的：验证type7类型下的机密性和完整性密级的右边界（最大值）
测试步骤：
1.设备下发“完整性为255、机密性为255”的标记策略，通过babbitMQ下发
2.客户端tcpreplay发送“完整性为255、机密性为255”的报文
3.服务端抓取并分析报文
4.设备移除标记策略，通过babbitMQ删除
预期结果：
1.设备策略下发成功，可以使用tupleacl --get查看
2.客户端发送报文成功
3.服务端抓取分析成功
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
    from Case_rbm.cipso_type7_level import index
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


class Test_cipso_type7_level():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.case1_mtLabel = index.case1_mtLabel
        self.pkt1_cfg = index.pkt1_cfg
        self.case2_mtLabel = index.case2_mtLabel
        self.pkt2_cfg = index.pkt2_cfg
        self.case3_mtLabel = index.case3_mtLabel
        self.pkt3_cfg = index.pkt3_cfg
        self.case4_mtLabel = index.case4_mtLabel
        self.pkt4_cfg = index.pkt4_cfg
        self.case5_mtLabel = index.case5_mtLabel
        self.pkt5_cfg = index.pkt5_cfg
        self.clr_env = clr_env
        clr_env.clear_env()


    @allure.feature('用例一：验证含type7标记策略的机密性和完整性都填的规则')
    def test_cipso_level_sensitivity_integrity(self):
        log.warning('用例一：验证含type7标记策略的机密性和完整性都填的规则')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2, cap_pcap3 = self.pkt1_cfg["capture"][0], \
                                                          self.pkt1_cfg["capture"][1], self.pkt1_cfg["capture"][2], \
                                                          self.pkt1_cfg["capture"][3], self.pkt1_cfg["capture"][4], self.pkt1_cfg["capture"][5]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2, c_pcap3 = self.pkt1_cfg["send"][0], self.pkt1_cfg["send"][1], \
                                        self.pkt1_cfg["send"][2], self.pkt1_cfg["send"][3], self.pkt1_cfg["send"][4]
        read_name1, read_id = self.pkt1_cfg["read"][0], self.pkt1_cfg["read"][1],
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case1_mtLabel)

        # 服务端抓取报文
        log.warning('验证客户端发送"机密性等级10、完整性等级13"的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt1_cfg["expect"][0])

        # 服务端抓取报文
        log.warning('验证客户端发送"机密性等级15、完整性等级13"的报文')
        fun.cmd(f"rm -rf /opt/pkt/{cap_pcap2}", 's')
        pre_cfg2 = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap2)
        log.warning('服务端设置抓取报文：{}'.format(pre_cfg2))
        fun.cmd(pre_cfg2, 's', thread=1)
        log.warning('step wait 20s')
        time.sleep(20)
        # 客户端发送报文
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap2)
        log.warning('客户端发送报文：{}'.format(send_cmd))
        fun.cmd(send_cmd, 'c')
        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        fun.pid_kill(cap_pcap2)
        log.warning('服务端检查报文是否存在：{}'.format(pcap_file))
        assert cap_pcap2 not in pcap_file

        # 服务端抓取报文
        log.warning('验证客户端发送"机密性等级10、完整性等级12"的报文')
        fun.cmd(f"rm -rf /opt/pkt/{cap_pcap3}", 's')
        pre_cfg3 = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap3)
        log.warning('服务端设置抓取报文：{}'.format(pre_cfg3))
        fun.cmd(pre_cfg3, 's', thread=1)
        log.warning('step wait 20s')
        time.sleep(20)
        # 客户端发送报文
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap3)
        log.warning('客户端发送报文：{}'.format(send_cmd))
        fun.cmd(send_cmd, 'c')
        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        fun.pid_kill(cap_pcap3)
        log.warning('服务端检查报文是否存在：{}'.format(pcap_file))
        assert cap_pcap3 not in pcap_file

        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case1_mtLabel)


    @allure.feature('用例二：验证含type7标记策略的只填机密性（BLP模型）规则 ')
    def test_cipso_level_sensitivity(self):
        log.warning('用例二：验证含type7标记策略的只填机密性（BLP模型）规则 ')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2 = self.pkt2_cfg["capture"][0], \
                                                          self.pkt2_cfg["capture"][1], self.pkt2_cfg["capture"][2], \
                                                          self.pkt2_cfg["capture"][3], self.pkt2_cfg["capture"][4]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2 = self.pkt2_cfg["send"][0], self.pkt2_cfg["send"][1], \
                                        self.pkt2_cfg["send"][2], self.pkt2_cfg["send"][3]
        read_name1, read_id = self.pkt2_cfg["read"][0], self.pkt2_cfg["read"][1],
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case2_mtLabel)

        # 服务端抓取报文
        log.warning('验证客户端发送"机密性等级13"的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt2_cfg["expect"][0])
        # 服务端抓取报文
        log.warning('验证客户端发送"机密性等级10"的报文')
        fun.cmd(f"rm -rf /opt/pkt/{cap_pcap2}", 's')
        pre_cfg2 = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap2)
        log.warning('服务端设置抓取报文：{}'.format(pre_cfg2))
        fun.cmd(pre_cfg2, 's', thread=1)
        log.warning('step wait 20s')
        time.sleep(20)
        # 客户端发送报文
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap2)
        log.warning('客户端发送报文：{}'.format(send_cmd))
        fun.cmd(send_cmd, 'c')
        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        fun.pid_kill(cap_pcap2)
        log.warning('服务端检查报文是否存在：{}'.format(pcap_file))
        assert cap_pcap2 not in pcap_file

        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case2_mtLabel)



    @allure.feature('用例三：验证含type7标记策略的只填完整性（BIBA模型）规则 ')
    def test_cipso_level_integrity(self):
        log.warning('用例三：验证含type7标记策略的只填完整性（BIBA模型）规则 ')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1, cap_pcap2 = self.pkt3_cfg["capture"][0], \
                                                          self.pkt3_cfg["capture"][1], self.pkt3_cfg["capture"][2], \
                                                          self.pkt3_cfg["capture"][3], self.pkt3_cfg["capture"][4]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1, c_pcap2 = self.pkt3_cfg["send"][0], self.pkt3_cfg["send"][1], \
                                        self.pkt3_cfg["send"][2], self.pkt3_cfg["send"][3]
        read_name1, read_id = self.pkt3_cfg["read"][0], self.pkt3_cfg["read"][1],
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case3_mtLabel)

        # 服务端抓取报文
        log.warning('验证客户端发送"完整性等级13"的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt3_cfg["expect"][0])
        # 服务端抓取报文
        log.warning('验证客户端发送"完整性等级15"的报文')
        fun.cmd(f"rm -rf /opt/pkt/{cap_pcap2}", 's')
        pre_cfg2 = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap2)
        log.warning('服务端设置抓取报文：{}'.format(pre_cfg2))
        fun.cmd(pre_cfg2, 's', thread=1)
        log.warning('step wait 20s')
        time.sleep(20)
        # 客户端发送报文
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap2)
        log.warning('客户端发送报文：{}'.format(send_cmd))
        fun.cmd(send_cmd, 'c')
        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        fun.pid_kill(cap_pcap1)
        log.warning('服务端检查报文是否存在：{}'.format(pcap_file))
        assert cap_pcap2 not in pcap_file
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case3_mtLabel)


    @allure.feature('用例四：验证type7类型下的机密性和完整性密级的左边界（最小值）')
    def test_cipso_level_sensitivity_integrity_minimum(self):
        log.warning('用例四：验证type7类型下的机密性和完整性密级的左边界（最小值）')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1 = self.pkt4_cfg["capture"][0], self.pkt4_cfg["capture"][1], \
                                                    self.pkt4_cfg["capture"][2], self.pkt4_cfg["capture"][3]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1 = self.pkt4_cfg["send"][0], self.pkt4_cfg["send"][1], self.pkt4_cfg["send"][2]
        read_name1, read_id = self.pkt4_cfg["read"][0], self.pkt4_cfg["read"][1],
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case4_mtLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送"机密性为1、完整性为1"的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt3_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case4_mtLabel)


    @allure.feature('用例五：验证type7类型下的机密性和完整性密级的右边界（最大值）')
    def test_cipso_level_sensitivity_integrity_maximum(self):
        log.warning('用例五：验证type7类型下的机密性和完整性密级的右边界（最大值）')
        # 接口名称，过滤规则，抓包数量，报文命名
        cap_iface, cap_filter, cap_num, cap_pcap1 = self.pkt5_cfg["capture"][0], self.pkt5_cfg["capture"][1], \
                                                    self.pkt5_cfg["capture"][2], self.pkt5_cfg["capture"][3]
        # 发送报文接口，发送报文数量，发送报文名称
        c_iface, c_num, c_pcap1 = self.pkt5_cfg["send"][0], self.pkt5_cfg["send"][1], self.pkt5_cfg["send"][2]
        read_name1, read_id = self.pkt5_cfg["read"][0], self.pkt5_cfg["read"][1],
        # 设备下发标记策略
        fun.send_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case5_mtLabel)
        # 服务端抓取报文
        log.warning('验证客户端发送"机密性为255、完整性为255"的报文')
        fun.client_send_server_pkt(cap_iface, cap_filter, cap_num, cap_pcap1, c_iface, c_num, c_pcap1, read_name1,
                                   read_id, self.pkt3_cfg["expect"][0])
        # 设备移除策略
        fun.delete_cipso(tool, rbmDomain, rbmExc, clientOpeIp, serverOpeIp, mtLabel=self.case5_mtLabel)


    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
