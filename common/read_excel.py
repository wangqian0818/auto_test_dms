#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/11/29 10:53

import ast
import logging

# 导入 xlrd 库,读excel表格
import xlrd

from common import baseinfo

try:
    import os, sys, time
except Exception as err:
    print('导入CPython内置函数库失败!错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

log = logging.getLogger(__name__)

http_ruleid = baseinfo.http_ruleid
ftp_ruleid = baseinfo.ftp_ruleid
smtp_ruleid = baseinfo.smtp_ruleid
tcp_ruleid = baseinfo.tcp_ruleid
app_ruleid = baseinfo.app_ruleid


# 从excel中读取数据，组装成字典类型
def read_xls(data_type=['http']):
    xls_path = 'C:\\Users\\admin\\Desktop\\自动化测试用例表.xls'
    # xls_path = 'C:\\Users\\admin\\Desktop\\自动化测试用例表_test.xls'
    # 打开刚才我们写入的 xls 文件
    wb = xlrd.open_workbook(xls_path)
    # 获取并打印 sheet 数量
    log.warning("sheet 数量:{}".format(wb.nsheets))
    # 获取并打印 sheet 名称
    log.warning("sheet 名称:{}".format(wb.sheet_names()))
    # 根据 sheet 索引获取内容
    http_sheet = wb.sheet_by_index(0)
    ftp_sheet = wb.sheet_by_index(1)
    mail_sheet = wb.sheet_by_index(2)
    keyword_sheet = wb.sheet_by_index(3)
    app_sheet = wb.sheet_by_index(4)
    # 也可根据 sheet 名称获取内容
    # sh = wb.sheet_by_name('成绩')
    # 获取并打印该 sheet 行数和列数
    # log.warning('---------------------------------------------------------------------------------------')
    # log.warning(u"sheet_%s 共 %d 行 %d 列" % (http_sheet.name, http_sheet.nrows, http_sheet.ncols))
    # log.warning(u"sheet_%s 共 %d 个用例" % (http_sheet.name, http_sheet.nrows - 3))
    # log.warning('---------------------------------------------------------------------------------------')
    # log.warning(u"sheet_%s 共 %d 行 %d 列" % (ftp_sheet.name, ftp_sheet.nrows, ftp_sheet.ncols))
    # log.warning(u"sheet_%s 共 %d 个用例" % (ftp_sheet.name, ftp_sheet.nrows - 3))
    # log.warning('---------------------------------------------------------------------------------------')
    # log.warning(u"sheet_%s 共 %d 行 %d 列" % (mail_sheet.name, mail_sheet.nrows, mail_sheet.ncols))
    # log.warning(u"sheet_%s 共 %d 个用例" % (mail_sheet.name, mail_sheet.nrows - 3))
    # log.warning('---------------------------------------------------------------------------------------')
    # log.warning(u"sheet_%s 共 %d 行 %d 列" % (keyword_sheet.name, keyword_sheet.nrows, keyword_sheet.ncols))
    # log.warning(u"sheet_%s 共 %d 个用例" % (keyword_sheet.name, keyword_sheet.nrows - 3))
    # log.warning('---------------------------------------------------------------------------------------')
    # log.warning(u"sheet_%s 共 %d 行 %d 列" % (app_sheet.name, app_sheet.nrows, app_sheet.ncols))
    # log.warning(u"sheet_%s 共 %d 个用例" % (app_sheet.name, app_sheet.nrows - 3))
    # log.warning('---------------------------------------------------------------------------------------')

    # 获取整行或整列的值
    # rows = http_sheet.row_values(0)  # 获取第一行内容
    # cols = http_sheet.col_values(1)  # 获取第二列内容
    # # 打印获取的行列值
    # log.warning("第一行的值为:", rows)
    # log.warning("第二列的值为:", cols)
    # # 获取单元格内容的数据类型
    # log.warning("第二行第一列的值类型为:", http_sheet.cell(1, 0).ctype)
    all_case_dict = {}
    for i in range(len(data_type)):
        if 'http' == data_type[i]:
            sheet = http_sheet
        elif 'ftp' == data_type[i]:
            sheet = ftp_sheet
        elif 'mail' == data_type[i]:
            sheet = mail_sheet
        elif 'keyword' == data_type[i]:
            sheet = keyword_sheet
        elif 'app' == data_type[i]:
            sheet = app_sheet
        else:
            log.warning('暂不存在该种类型的sheet_{},请检查后再试'.format(data_type))
        pol_list = []
        url_list = []
        assert_list = []
        log.warning(
            '\n\n\n===================================================== sheet_{} 总用例 ================================================'.format(
                sheet.name))

        for row_num in range(4, sheet.nrows + 1):
            log.warning(
                '------------------------------------ 第{}行用例 ------------------------------------'.format(row_num))
            # 解析策略内容，将content组装成list
            policy_str = sheet.cell_value(row_num - 1, 0)
            # log.warning('policy_str:{}'.format(policy_str))
            policy_list = []

            if data_type[i] == 'app':
                policy_str = policy_str.replace('\n', '').replace(' ', '')
                # log.warning('policy_str: {}'.format(policy_str))
                if len(policy_str.split('Action')) == 2:
                    str = '{"Action' + policy_str.split('Action')[1][:-1]
                    polict_dict = ast.literal_eval(str)
                    polict_dict['RuleId'] = app_ruleid
                    log.warning('polict_dict:{}'.format(polict_dict))
                    policy_list.append(polict_dict)
                elif len(policy_str.split('Action')) == 3:
                    list = policy_str.split('Action')
                    policy_dict1 = ast.literal_eval('{"Action' + list[1][:-3])
                    policy_dict2 = ast.literal_eval('{"Action' + list[2][:-1])
                    policy_dict1['RuleId'] = app_ruleid
                    policy_dict2['RuleId'] = app_ruleid + 1
                    log.warning('policy_dict1:{}'.format(policy_dict1))
                    log.warning('policy_dict2:{}'.format(policy_dict2))
                    # 将单个或者多个字典添加到小list中
                    policy_list.append(policy_dict1)
                    policy_list.append(policy_dict2)
            else:
                if len(policy_str.split('{')) == 2:
                    # 将字典类型的字符串转成字典
                    polict_dict = ast.literal_eval(policy_str)[0]
                    if data_type[i] == 'http':
                        polict_dict['RuleId'] = http_ruleid
                    elif data_type[i] == 'ftp':
                        polict_dict['RuleId'] = ftp_ruleid
                    elif data_type[i] == 'mail':
                        polict_dict['RuleId'] = smtp_ruleid
                    elif data_type[i] == 'keyword':
                        polict_dict['RuleId'] = tcp_ruleid
                    log.warning('polict_dict:{}'.format(polict_dict))
                    policy_list.append(polict_dict)
                else:
                    # 使用'}'分割完后会产生三个元素的列表
                    ls = policy_str.split('}')
                    # 拿到前两个，先将\n替换成空，再截取掉前面一两个中括号，尾部添加}，这样组成的字符串就是字典格式的，再转成字典
                    policy_dict1 = ast.literal_eval(ls[0].replace('\n', '')[1:] + '}')
                    policy_dict2 = ast.literal_eval(ls[1].replace('\n', '')[2:] + '}')
                    # 添加键值对，内容为  'RuleId': id
                    if data_type[i] == 'http':
                        ruleid = http_ruleid
                    elif data_type[i] == 'ftp':
                        ruleid = ftp_ruleid
                    elif data_type[i] == 'mail':
                        ruleid = smtp_ruleid
                    elif data_type[i] == 'keyword':
                        ruleid = tcp_ruleid
                    elif data_type[i] == 'app':
                        ruleid = app_ruleid
                    policy_dict1['RuleId'] = ruleid
                    policy_dict2['RuleId'] = ruleid + 1
                    log.warning('policy_dict1:{}'.format(policy_dict1))
                    log.warning('policy_dict2:{}'.format(policy_dict2))
                    # 将单个或者多个字典添加到小list中
                    policy_list.append(policy_dict1)
                    policy_list.append(policy_dict2)
            # 将该list添加进总列表中
            pol_list.append(policy_list)

            # 解析 验证的url
            request_list = []
            excel_str = sheet.cell_value(row_num - 1, 1)
            if data_type[i] == 'http':
                request_list = excel_str.split('+')
            elif data_type[i] == 'ftp':
                request_list = excel_str.split('\n')
            elif data_type[i] == 'mail':
                request_list = excel_str.replace(':\n', ':').replace('：\n', ':').split('\n')
            elif data_type[i] == 'keyword':
                ls = excel_str.replace(':\n', ':').replace('：\n', ':').split('\n')
                request_list = []
                flag = True
                for req_num in range(len(ls)):
                    if 'para' in ls[req_num]:
                        para_req = ls[req_num]
                        if req_num < len(ls):
                            for j in range(req_num + 1, len(ls)):
                                para_req += '\n' + ls[j]
                            ls[req_num] = para_req
                            request_list.append(ls[req_num])
                        flag = False
                    if flag:
                        request_list.append(ls[req_num])
                # print(request_list)
            elif data_type[i] == 'app':
                if 'get+URL' == excel_str:
                    request_list = excel_str.split('+')
                elif 'wget' in excel_str:
                    request_list = excel_str.split(' ')
                else:
                    list = excel_str.replace('\n', '').split('）')
                    request_list.append(list[1].split('（')[0])
                    request_list.append(list[2].split('（')[0])
                    request_list.append(list[3])
            else:
                log.warning('暂不存在该种类型的sheet_{},请检查后再试'.format(data_type[i]))
            log.warning('request_list:{}'.format(request_list))

            url_list.append(request_list)

            # 解析 断言方式
            assert_str = sheet.cell_value(row_num - 1, 2)
            log.warning('assert_str：{}'.format(assert_str))
            assert_list.append(assert_str)

        log.warning('\n==========================================================\n')
        case_dict = {}
        case_dict['content'] = pol_list
        case_dict['check'] = url_list
        case_dict['assert'] = assert_list
        # log.warning(case_dict)
        all_case_dict[data_type[i]] = case_dict
    return all_case_dict


if __name__ == '__main__':
    # 'http', 'ftp', 'mail', 'keyword', 'app'
    all_case_dict = read_xls(data_type=['keyword'])
    # log.warning('\n==========================================================\n')
    # log.warning(all_case_dict['http']['content'])
    # log.warning(all_case_dict['http']['check'])
    # log.warning(all_case_dict['http']['assert'])
    # log.warning('\n==========================================================\n')
    # log.warning(all_case_dict['ftp']['content'])
    # log.warning(all_case_dict['ftp']['check'])
    # log.warning(all_case_dict['ftp']['assert'])
    # log.warning('\n==========================================================\n')
    # log.warning(all_case_dict['keyword']['content'])
    # log.warning(all_case_dict['keyword']['check'])
    # log.warning(all_case_dict['keyword']['assert'])
    # log.warning('\n==========================================================\n')
    # log.warning(all_case_dict['keyword']['content'])
    # log.warning(all_case_dict['keyword']['check'])
    # log.warning(all_case_dict['keyword']['assert'])
    # log.warning('\n==========================================================\n')
    # log.warning(all_case_dict['keyword']['content'])
    # log.warning(all_case_dict['keyword']['check'])
    # log.warning(all_case_dict['keyword']['assert'])
    # log.warning(all_case_dict['app'])

