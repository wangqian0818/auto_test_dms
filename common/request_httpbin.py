#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/11/3 14:47


import requests

# pip install requests
# http://cn.python-requests.org/zh_CN/latest/
URL = r'http://10.10.101.149:8080/'

if __name__ == '__main__':
    r = requests.get(URL + 'get')
    log.warning(r.text)
    r = requests.post(URL + 'post')
    log.warning(r.text)
