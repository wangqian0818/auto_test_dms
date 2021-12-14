#!/usr/bin/env python
# coding: utf-8
'''
修订人：王谦
修订时间：2021/06/28
修订内容：新增方法：read_verion() 修订方法：pytest_html_results_summary()  实现html的log中显示当前设备的组件版本号
'''

import logging
from datetime import datetime

log = logging.getLogger(__name__)
from py._xmlgen import html

from common import baseinfo
import os

import pytest
import time
from _pytest.runner import runtestprotocol

# from py.xml import html

version = baseinfo.version  # 获取版本号
base_path = os.path.dirname(os.path.abspath(__file__))
base_path = base_path.replace('\\', '/')
# result_file = base_path + '/Logs/' + str(version) + '/' + current_time + '/result_temp.txt'
result_file = base_path + '/Logs/' + str(version) + '/result_temp.txt'


def pytest_runtest_protocol(item, nextitem):
    # f = open('./result_temp.txt', 'a+')
    # # old = sys.stdout  # 将当前系统输出储存到临时变量
    # sys.stdout = f  # 输出重定向到文件
    # f.close()
    reports = runtestprotocol(item, nextitem=nextitem)
    num = 0
    for report in reports:
        if report.when == 'setup' and report.outcome == 'passed':
            # log.warning("\n\n\n")
            # log.warning('\n\n%s -- %s -- %s' % (item.name, report.when, report.outcome))
            num += 1
        elif report.when == 'setup' and report.outcome == 'skipped':
            # log.warning("\n\n\n")
            # log.warning('\n\n%s -- %s -- %s' % (item.name, report.when, report.outcome))
            num += 99
        elif report.when == 'call' and report.outcome == 'passed':
            # log.warning('%s -- %s -- %s' % (item.name, report.when, report.outcome))
            num += 1
        elif report.when == 'teardown' and report.outcome == 'passed':
            # log.warning('%s -- %s -- %s' % (item.name, report.when, report.outcome))
            num += 1
    # log.warning("num: ",num)
    # 将用例执行结果写入到 result_temp.txt 文件中
    # file = open('./result_temp.txt', 'a+')
    file = open(result_file, 'a+')
    startStr = "\n start----------------------------------------------------------------------------------------------------"
    # file.write(startStr)
    log.warning(startStr)
    str = ''
    if num == 3:
        str = '\nresult: %s -- %s' % (item.name, report.outcome)
        log.warning(str)
    elif num == 100:
        str = '\nresult: %s -- skipped' % (item.name)
        log.warning(str)
    else:
        str = '\nresult: %s -- failed' % (item.name)
        log.warning(str)
    # 写入执行结果并刷新
    file.write(str)
    file.flush()
    file.write('\t\t%s' % time.strftime('%Y%m%d_%H-%M-%S', time.localtime(time.time())))
    file.flush()
    endStr = "\n end----------------------------------------------------------------------------------------------------"
    # file.write(endStr)
    log.warning(endStr)
    return True


# @pytest.fixture()
# def clear_result_temp():
#     log.warning("================== 清空数据")
#     with open('./result_temp.txt', 'w') as f1:
#         f1.seek(0)
#         f1.truncate()
#     yield
#     time.sleep(10)
#     file = open('result_temp.txt', 'r')
#     lines = file.read().split('\n')
#     res = []
#     for line in lines:
#         if 'result: ' in line:
#             res.append(line)
#     log.warning("结果行内容为：",res)


# def pytest_terminal_summary(terminalreporter, exitstatus, config):
#     '''收集测试结果'''
#     log.warning(terminalreporter.stats)
#     log.warning("total:", terminalreporter._numcollected)
#     log.warning('passed:', len(terminalreporter.stats.get('passed', [])))
#     log.warning('failed:', len(terminalreporter.stats.get('failed', [])))
#     log.warning('error:', len(terminalreporter.stats.get('error', [])))
#     log.warning('skipped:', len(terminalreporter.stats.get('skipped', [])))
#     log.warning('成功率：%.2f' % (len(terminalreporter.stats.get('passed', [])) / terminalreporter._numcollected * 100) + '%')
#     # terminalreporter._sessionstarttime 会话开始时间
#     duration = time.time() - terminalreporter._sessionstarttime
#     log.warning('total times:', duration, 'seconds')


# turn . into √，turn F into x, turn E into 0
def pytest_report_teststatus(report, config):
    '''turn . into √，turn F into x, turn E into 0'''
    if report.when == 'call' and report.failed:
        return (report.outcome, 'x', 'failed')
    if report.when == 'call' and report.passed:
        return (report.outcome, '√', 'passed')
    if report.when == 'setup' and report.failed:
        return (report.outcome, '0', 'error')


# 用例html的格式设置  ======================================================================
def pytest_configure(config):
    # 添加接口地址与项目名称
    config._metadata["设备IP"] = baseinfo.gwManageIp
    config._metadata['用例执行时间'] = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    # 删除Java_Home
    config._metadata.pop("JAVA_HOME")


@pytest.mark.hookwrapper
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    report.description = str(item.function.__doc__)
    report.nodeid = report.nodeid.encode("utf-8").decode("unicode_escape")


@pytest.mark.optionalhook
def pytest_html_results_table_header(cells):
    cells.insert(1, html.th('Time', class_='sortable time', col='time'))
    cells.insert(2, html.th('Test_nodeId'))
    # cells.insert(2, html.th('Description'))
    cells.pop(-1)  # 删除link列
    cells.pop(-2)  # 删除 用例 列


@pytest.mark.optionalhook
def pytest_html_results_table_row(report, cells):
    cells.insert(1, html.td(datetime.utcnow(), class_='col-time'))
    cells.insert(2, html.td(report.nodeid))
    # cells.insert(2, html.td(report.description))
    cells.pop(-1)  # 删除link列
    cells.pop(-2)  # 删除 用例 列
    # if report.passed:
    #   del cells[:]    # 如果用例passed，删除所有单元格


def read_verion():
    version_file = 'dut_version.txt'
    with open(version_file, 'r') as file:
        lines = file.readlines()
        return lines
        # for line in file.readlines():
        #     log.warning(line.strip())


@pytest.mark.optionalhook
def pytest_html_results_summary(prefix):
    prefix.extend([html.p("所属部门: 卓讯-合肥测试部")])
    prefix.extend([html.p("测试人员: 王谦")])
    lines = read_verion()
    for line in lines:
        prefix.extend([html.p("【 " + line.strip() + " 】")])


# 命令行传参  --cmdopt  ==================================================================
def pytest_addoption(parser):
    parser.addoption(
        "--cmdopt", action="store", default="type1", help="my option: type1 or type2"
    )


@pytest.fixture
def cmdopt(request):
    return request.config.getoption("--cmdopt")

# ==========================================================================================

# 16、如果login失败，则标记失败，加了参数autouse=true后，所有用例自动调用该fixture   case1用
# @pytest.fixture(scope="function")
# def login(request):
#     user = request.param["user"]
#     psw = request.param["psw"]
#     log.warning("模块名为：【%s】, 正在操作登录，账号：%s, 密码：%s" % (request.module.__name__, user, psw))
#     if psw:
#         return True
#     else:
#         return False

# if __name__ == '__main__':
#     html_time_name = './report/py_html/report_' + str(time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())) + '.html'
#     html_name = './report/py_html/report.html'
#     # case1 = 'E://Projects_Py//auto_test_1214//auto_test//Case_rbm//case_01_wq//function.py'
#     case1 = 'E://卓讯//自动化测试//auto_test//Case_rbm//case_01_wq//function.py'
#     case2 = 'E://Projects_Py//auto_test_1214//auto_test//Case_rbm//case_02_wq//test_allure.py'
#     case3 = 'E://Projects_Py//auto_test_1214//auto_test//Case_rbm//case_02_wq//test_02.py'
#     add_css = '--self-contained-html'  # 将css融入到html中，便于分享
#     fail_rerun = '--reruns=6'  # 失败后重新运行的次数
#     log.warning_consol = '-s'  # 将log.warning输出到控制台,但是html捕获不到log.warning输出，但是如果加了'--capture=sys'输出就转到html页面了
#     log.warning_html = '--capture=sys'  # 加了-s后，会将log.warning输出到控制台，但是默认的输出到html就失效了，如果加'--capture=sys'则会控制台失效，输出到html文件
#     cmdopt = '--cmdopt=type2'
#     r = '-r'
#     mark = '-m=webtest'  # 只运行标记了webtest的用例，标记：@pytest.mark.webtest
#     key = '-k http'  # 关键字过滤，只运行包含该关键字的用例
#     last_fail = '--lf'  # 只执行上次运行失败的用例，如果没有失败的则全部运行  `pytest --lf` 即可
#     tb = '--tb=line'  # style 的值可以设置6种打印模式：auto/long/short/line/native/no
#     durations = '--durations=1'  # 如果N为0，就是统计所有用例的执行时间，如果为3，则是统计运行时间最长的三个用例
#     show_fixture = '--setup-show'  # 查看用例使用了哪些fixture
#     instafail = '--instafail'  # 实时查看用例报错，不用等到所有用例执行完统一报错，这样看错更直观，可和 --tb=line 搭配使用
#
#     # pytest.main([log.warning_html,case1, '--html=' + html_time_name, add_css,tb,'-vv',durations])   # 输出到html页面
#     # pytest.main([log.warning_consol, case1])  # 输出到控制台
#
#     # 使用allure做报告
#
#     allure_dir = '--alluredir=./report/allure_raw'
#
#     pytest.main([case1, allure_dir])
#
#     os.system('allure generate ./report/allure_raw -o ./report/allure_html --clean')
#     os.system('allure serve ./report/allure_raw')  # 生成报告并打开报告方法一
#     # os.system('allure open -h 127.0.0.1 -p 8083 ./report/allure_html')   # 生成报告并打开报告方法一
