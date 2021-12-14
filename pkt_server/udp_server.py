import socket
import sys
import time
res_data = 'Thanks'
u_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
def udp_server(server_ip, server_port):
    u_server.bind((server_ip, server_port))
    print('Socket will bind any address')
    print('Socket bind port %d' % server_port)
    while True:
        data, addr = u_server.recvfrom(1024)
        print("rec:%s" % data.decode('utf-8'))
        print("from:%s:%s" % addr)
        u_server.sendto(res_data.encode('utf-8'), addr)
try:
    udp_server(sys.argv[1], int(sys.argv[2]))
    # udp_server(8887)
    u_server.close()
except Exception as err:
    print(err)
    sys.exit(0)