import socket

import time
host = 'localhost'
port = 5103

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) #在客户端开启心跳维护
client.connect((host, port))

def send(msg):
    pass

while True:
    client.send('hello world\r\n'.encode())
    print('send data')
    time.sleep(1) #如果想验证长时间没发数据，SOCKET连接会不会断开，则可以设置时间长一点