#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/12/10 11:02
import getopt
import os
import socket
import struct

# host = '192.168.30.47'
# port = 2288
import sys

fmt = '128si'
send_buffer = 4096


def tcp_socket_file(host, port, filepath):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    # filepath = input("enter file path:")
    filename = os.path.split(filepath)[1]
    filesize = os.path.getsize(filepath)
    print("filename:" + filename + "\nfilesize:" + str(filesize))
    head = struct.pack(fmt, filename.encode(), filesize)
    # print("\nhead size:" + str(head.__len__()) + "\n" + str(head))
    sock.sendall(head)
    restSize = filesize
    fd = open(filepath, 'rb')
    count = 0
    while restSize >= send_buffer:
        data = fd.read(send_buffer)
        sock.sendall(data)
        restSize = restSize - send_buffer
        print(str(count) + " ")
        count = count + 1
    data = fd.read(restSize)
    sock.sendall(data)
    fd.close()
    print("successfully sent")


if __name__ == '__main__':
    # python3 tcp_client_file.py -f 11.txt
    # python3 tcp_client_file.py --filename=11.txt
    host = '192.168.30.47'
    # host = '127.0.0.1'
    # host = '10.10.101.26'
    port = 2288
    filename = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "f:", ['filename='])
        for opt, arg in opts:
            if opt in ['-f', '--filename']:
                filename = arg
        # print('filename:{}'.format(filename))
    except:
        print("Error")
    tcp_socket_file(host, port, filename)

