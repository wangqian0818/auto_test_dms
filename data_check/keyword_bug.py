#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/11/5 17:18
from common import baseinfo
from data_check import http_check
import logging

log = logging.getLogger(__name__)

def keyword_bug():
    url = 'http://192.168.30.111:2287'
    url_data = 'http://192.168.30.111:2287/123.txt'
    url_data1 = 'http://192.168.30.111:2287/123456789.txt'

    data_get_fail = 0
    data_post_fail = 0
    data1_get_fail = 0
    data1_post_fail = 0

    for i in range(100):
        log.warning('第{}次请求'.format(i + 1))
        content_get = http_check.http_get(url)
        assert baseinfo.http_content == content_get
        content_post = http_check.http_post(url)
        assert baseinfo.http_content == content_post

        get_result = http_check.http_get(url_data)
        if 0 == get_result:
            data_get_fail += 1
        post_result = http_check.http_post(url_data)
        if 0 == post_result:
            data_post_fail += 1

        get_result = http_check.http_get(url_data1)
        if 0 == get_result:
            data1_get_fail += 1
        post_result = http_check.http_post(url_data1)
        if 0 == post_result:
            data1_post_fail += 1

    log.warning('运行100次\ndata_get_fail：{}\ndata_post_fail：{}\ndata1_get_fail：{}\ndata1_post_fail：{}'.format(data_get_fail,
                                                                                                      data_post_fail,
                                                                                                      data1_get_fail,
                                                                                                      data1_post_fail))


if __name__ == '__main__':
    keyword_bug()
