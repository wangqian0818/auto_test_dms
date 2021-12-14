#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/12/12 13:14
import getopt
import os
import socket
import sys


send_buffer = 1024

def Get_FilePath_FileName_FileExt(filename):
    filepath, tempfilename = os.path.split(filename)
    shotname, extension = os.path.splitext(tempfilename)
    return filepath, shotname, extension


def udp_socket_file(host, port, filepath):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # filepath, shotname, extension = Get_FilePath_FileName_FileExt(filename)
    filename = os.path.split(filepath)[1]
    filesize = os.path.getsize(filepath)
    print('filename:', filename)
    print('filesize:', filesize)
    client_addr = (host, port)
    fd = open(filename, 'rb')
    restSize = filesize
    count = 0
    while restSize >= send_buffer:
        data = fd.read(send_buffer)
        s.sendto(data, client_addr)
        restSize = restSize - send_buffer
        print(str(count) + " ")
        count = count + 1

        # data = bytes(filename, encoding="utf8")
        # print(str(count) + 'byte')
        # s.sendto('end'.encode('utf-8'), client_addr)
        # break
        # data, server_addr = s.recvfrom(1024)
        # count += 1
        # print('recircled' + str(count))
    data = fd.read(1024)
    s.sendto(data, client_addr)
    s.close()
    fd.close()
    print("successfully sent")
    # for data in [b'Michael',b'Tracy',b'Sarah']:
    #  s.sendto(data,('127.0.0.1',9999))
    #  print(s.recv(1024).decode('utf-8'))
    # s.close()


if __name__ == '__main__':
    # python3 tcp_client_file.py -f 11.txt
    # python3 tcp_client_file.py --filename=11.txt
    host = '192.168.30.47'
    # host = '127.0.0.1'
    # host = '10.10.101.26'
    port = 2289
    filename = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "f:", ['filename='])
        for opt, arg in opts:
            if opt in ['-f', '--filename']:
                filename = arg
        # print('filename:{}'.format(filename))
    except:
        print("Error")

    # filename = 'udp_file.txt'
    udp_socket_file(host, port, filename)
