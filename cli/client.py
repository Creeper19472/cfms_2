import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib

import json
import time
import os, sys

class ClientConn:

    def __init__(self, client, **kwargs): #!!注意，self.thread_name 在调用类定义！

        self.kwargs = kwargs
        
        self.client = client

        self.BUFFER_SIZE = 1024

        self.encrypted_connection = True

        self.aes_key = None

    def aes_encrypt(self, plain_text, key):

        cipher = AES.new(key, AES.MODE_CBC) # 使用CBC模式

        encrypted_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))

        iv = cipher.iv

        return iv + encrypted_text

    # 解密

    def aes_decrypt(self , encrypted_text, key):

        iv = encrypted_text[:16]

        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_text = unpad(cipher.decrypt(encrypted_text[16:]), AES.block_size)

        return decrypted_text.decode()

    def send(self, msg): # 不内置 json.dumps(): some objects are not hashable
        # self.log.logger.debug(f"raw message to send: {msg}")
        msg_to_send = msg.encode()
        if self.encrypted_connection:
            encrypted_data = self.aes_encrypt(msg, self.aes_key) # aes_encrypt() 接受文本
            self.client.sendall(encrypted_data)
        else:
            self.client.sendall(msg_to_send)

    def recv(self):
        total_data = bytes()
        while True:
            # 将收到的数据拼接起来
            data = self.client.recv(self.BUFFER_SIZE)
            total_data += data
            if len(data) < self.BUFFER_SIZE:
                break
        if self.encrypted_connection:
            decoded = self.aes_decrypt(total_data, self.aes_key)
        else:
            decoded = total_data.decode()
        # self.log.logger.debug(f"received decoded message: {decoded}")
        return decoded

def aes_encrypt(plain_text, key):

    cipher = AES.new(key, AES.MODE_CBC) # 使用CBC模式

    encrypted_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))

    iv = cipher.iv

    return iv + encrypted_text

# 解密

def aes_decrypt(encrypted_text, key):

    iv = encrypted_text[:16]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_text = unpad(cipher.decrypt(encrypted_text[16:]), AES.block_size)

    return decrypted_text.decode()


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


if os.path.exists(f"saved_certs/{host+str(port)}.pem"):
    with open(f"saved_certs/{host+str(port)}.pem","+r") as saved_pub:
        if (publicKey:=json.loads(response)['public_key']) == saved_pub.read():
            pass
        else:
            print("WARNING! 服务器返回了一个与本地保存的证书不符的新证书。")
            print("这可能意味着服务器已被重置；但若非如此，则意味着您可能已遭受中间人攻击。")
            choice = input("您确定要继续吗(Y/N)? ")
            if choice.upper() == "Y":
                print("将覆盖本地已存在的证书文件。")
            else:
                sys.exit()

with open(f"saved_certs/{host+str(port)}.pem","+a") as pub_file:
    pub_file.truncate(0) # 清空
    pub_file.write(publicKey:=json.loads(response)['public_key'])


publicKey = RSA.import_key(json.loads(response)['public_key'])
# print(publicKey)
# 加密

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


data_key = get_random_bytes(32) # 生成对称用密钥


cipher = PKCS1_OAEP.new(publicKey)

aes_cipher = AES.new(data_key, AES.MODE_CBC)

encrypted_data = cipher.encrypt(data_key)
client.sendall(encrypted_data)

# data_key = get_random_bytes(32) # 生成对称用密钥

print(data_key)

response = aes_decrypt(client.recv(1024), data_key)

print(json.loads(response))

if (loaded_response := json.loads(response))["code"] == 0:
    print("success")

# 初始化对象 ClientConn
object_conn = ClientConn(client)
object_conn.aes_key = data_key

raw_passwd = "123456"
sha256_obj = hashlib.sha256()
sha256_obj.update(raw_passwd.encode())

request_data = {
    "version": 1,
    "request": "login",
    "data": {
        "username": "admin",
        "password": f"{sha256_obj.hexdigest()}"
        },
    "token": ""
    }

"""
request 必须包含的要素：

request: 请求的命令。
data: 包含请求所需的数据。
token: 登录时可不填；用于执行各项操作。
若未登录应留空。
"""

object_conn.send(json.dumps(request_data))
received = object_conn.recv()
print("Received: {}".format(loaded:=json.loads(received)))

token = loaded["token"]
# username = loaded["username"]

count = 0
while count < 10:
    count += 1

    time.sleep(1)
    
    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "refreshToken",
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))
    received = object_conn.recv()
    print("Received: {}".format(received))

    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "getDir",
            "data": {"id": "dir01"},
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))

    received = object_conn.recv()
    print("Received: {}".format(received))

    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "operateFile",
            "data": {"file_id": "C00001",
                     "action": "read"},
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))

    received = object_conn.recv()
    print("Received: {}".format(received))

    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "getPolicy",
            "data": {"policy_id": "login_retry"},
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))

    received = object_conn.recv()
    print("Received: {}".format(received))

    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "getAvatar",
            "data": {"username": "admin"},
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))

    received = object_conn.recv()
    print("Received: {}".format(received))

    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "getRootDir",
            "data": {},
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))

    received = object_conn.recv()
    print("Received: {}".format(received))

    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "uploadFile",
            "data": {
                "directory_id": "",
                "file_id": "testupload1",
                # "filename": ""
            },
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))

    received = object_conn.recv()
    print("Received: {}".format(received))

    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "operateFile",
            "data": {
                "action": "write",
                "file_id": "testupload1",
                # "filename": ""
            },
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))

    received = object_conn.recv()
    print("Received: {}".format(received))

    # object_conn.send(json.dumps(
    #     {
    #         "version": 1,
    #         "request": "operateFile",
    #         "data": {
    #             "action": "recover",
    #             "file_id": "testupload1",
    #             # "filename": ""
    #         },
    #         "auth": {
    #             "username": "admin",
    #             "token":  token
    #         }
    #      }
    # ))

    # received = object_conn.recv()
    # print("Received: {}".format(received))

    # object_conn.send(json.dumps(
    #     {
    #         "version": 1,
    #         "request": "operateFile",
    #         "data": {
    #             "action": "permanently_delete",
    #             "file_id": "testupload1",
    #             # "filename": ""
    #         },
    #         "auth": {
    #             "username": "admin",
    #             "token":  token
    #         }
    #      }
    # ))

    # received = object_conn.recv()
    # print("Received: {}".format(received))

    # object_conn.send(json.dumps(
    #     {
    #         "version": 1,
    #         "request": "shutdown",
    #         "data": {
    #         },
    #         "auth": {
    #             "username": "admin",
    #             "token":  token
    #         }
    #      }
    # ))

    # received = object_conn.recv()
    # print("Received: {}".format(received))

    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "createUser",
            "data": {
                "username": "testuser",
                "password": "123456"
            },
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))

    received = object_conn.recv()
    print("Received: {}".format(received))

    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "createGroup",
            "data": {
                "group_name": "testusergroup",
                "rights": {
                    "permanently_delete": {
                        "expire": 0
                    }
                },
                "members": ["admin"]
            },
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))

    received = object_conn.recv()
    print("Received: {}".format(received))

    object_conn.send(json.dumps(
        {
            "version": 1,
            "request": "getUserProperties",
            "data": {
                "username": "guest"
            },
            "auth": {
                "username": "admin",
                "token":  token
            }
         }
    ))

    received = object_conn.recv()
    print("Received: {}".format(received))



object_conn.send(json.dumps({
    "version": 1,
    "request": "disconnect"
}))
received = object_conn.recv()
print("Received: {}".format(received))

object_conn.client.close()

sys.exit()