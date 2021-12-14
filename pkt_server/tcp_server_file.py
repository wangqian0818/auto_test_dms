#!/usr/bin/env python
# coding: utf-8
# @TIME : 2021/12/10 11:01
import socket
import struct

# host = '127.0.0.1'
# port = 2288
fmt = '128si'  # 文件名最长128 i表示文件大小 i的数据类型决定了最大能够传输多大的文件
recv_buffer = 4096


def tcp_socket_file(host, port):
    listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenSock.bind((host, port))
    # 加上while，服务不停，一直等待接收文件
    while True:
        listenSock.listen(5)
        conn, addr = listenSock.accept()
        headsize = struct.calcsize(fmt)
        head = conn.recv(headsize)
        filename = struct.unpack(fmt, head)[0].decode().rstrip('\0')  # 要删掉用来补齐128个字节的空字符
        filename = 'C:\\Users\\admin\\Desktop\\' + filename
        # filename = '/opt/' + filename
        filesize = struct.unpack(fmt, head)[1]
        print("filename:" + filename + "\nfilesize:" + str(filesize))
        recved_size = 0
        fd = open(filename, 'wb')
        count = 0
        while True:
            data = conn.recv(recv_buffer)
            recved_size = recved_size + len(data)  # 虽然buffer大小是4096，但不一定能收满4096
            fd.write(data)
            if recved_size == filesize:
                break
        fd.close()
        print("new file\n")


if __name__ == '__main__':
    host = '127.0.0.1'
    port = 2288
    tcp_socket_file(host, port)
