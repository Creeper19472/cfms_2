import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import json
import time


host = 'localhost'
port = 5103

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) #在客户端开启心跳维护
client.connect((host, port))

message = "hello"

client.sendall(message.encode())
response = str(client.recv(1024), 'ascii')
print("Received: {}".format(response))

client.sendall("enableEncryption".encode())
response = str(client.recv(1024), 'ascii')
print("Received: {}".format(response))

publicKey = RSA.import_key(json.loads(response)['public_key'])
# print(publicKey)
# 加密

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


data_key = get_random_bytes(32) # 生成对称用密钥


cipher = PKCS1_OAEP.new(publicKey)
encrypted_data = cipher.encrypt(data_key)
client.sendall(encrypted_data)

aes_cipher = AES.new(data_key, AES.MODE_CBC)

response = aes_cipher.decrypt(client.recv(1024))
print(response.decode())
print("Received: {}".format(response))


# client.sendall()