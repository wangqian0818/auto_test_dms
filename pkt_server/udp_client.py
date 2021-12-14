import socket
import sys
u_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
send_data = 'hello world'
def udp_client(server_ip,server_port):
    while True:
        u_client.sendto(send_data.encode('utf-8'), (server_ip, server_port))
        data, addr = u_client.recvfrom(1024)
        print("rec:%s" % data.decode('utf-8'))
        break
try:
    udp_client(sys.argv[1], int(sys.argv[2]))
    #udp_client('10.10.100.5', 8887)
    u_client.close()
except Exception as err:
    print(err)
    sys.exit(0)