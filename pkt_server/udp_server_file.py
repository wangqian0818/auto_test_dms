#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/12/12 13:13

import socket

count = 0
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_addr = ('127.0.0.1', 2288)
s.bind(server_addr)

print('Bind UDP on 2288...')
while True:
    if count == 0:
        data, client_addr = s.recvfrom(1024)
        print('connected from{}: {}'.format(client_addr, data))
        f = open(data, 'wb')
    data, client_addr = s.recvfrom(1024)
    if str(data) != "b'end'":
        f.write(data)
        print('recieved ' + str(count) + ' byte')
    else:
        break
    s.sendto('ok'.encode('utf-8'), client_addr)
    count += 1
print('recercled' + str(count))
f.close()
s.close()

# data, addr = s.recvfrom(1024)
# print('Received from %s:%s' %addr)
# s.sendto(b'Hello, %s!' %data, addr)
