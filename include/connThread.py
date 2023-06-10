# connThread.py

import threading
import time
import gettext
import sys
import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import base64
import sqlite3

from include.bulitin_class.users import Users
from include.bulitin_class.documents import Documents

class ConnThreads(threading.Thread):
    def __init__(self, target, name, args=(), kwargs={}):
        super().__init__()
        self.target = target
        self.name = name # 只能是这个变量名
        # 传给真正的处理类
        self.args = args
        self.kwargs = kwargs

    def run(self):
        target_class = self.target(self.name, *self.args, **self.kwargs)

        try:
            target_class.main()
        except Exception as e:
            e.add_note("看起来线程内部的运行出现了问题。")
            raise

class ConnHandler():
    def __init__(self, thread_name, *args, **kwargs): #!!注意，self.thread_name 在调用类定义！
        self.root_abspath = kwargs["root_abspath"]

        self.args = args
        self.kwargs = kwargs
        self.thread_name = thread_name

        self.conn = kwargs["conn"]
        self.addr = kwargs["addr"]

        self.db_conn = sqlite3.connect(f"{self.root_abspath}/general.db")

        self.config = kwargs["toml_config"] # 导入配置字典

        self.locale = self.config['general']['locale']
        

        sys.path.append(f"{self.root_abspath}/include/") # 增加导入位置
        # sys.path.append(f"{self.root_abspath}/include/class")

        from logtool import LogClass
        self.log = LogClass(logname=f"main.connHandler.{self.thread_name}", filepath=f'{self.root_abspath}/main.log')

        # from bulitin_class.users import Users

        self.BUFFER_SIZE = 1024

        self.encrypted_connection = False

        self.__initRSA()
        self.aes_key = None
        
    def __initRSA(self):
        with open(f"{self.root_abspath}/content/auth/pri.pem", "rb") as pri_file:
            self.private_key = RSA.import_key(pri_file.read())
        self.pri_cipher = PKCS1_OAEP.new(self.private_key)

        with open(f"{self.root_abspath}/content/auth/pub.pem", "rb") as pub_file:
            self.public_key = RSA.import_key(pub_file.read())
        self.pub_cipher = PKCS1_OAEP.new(self.public_key)

    def aes_encrypt(self, plain_text, key):

        cipher = AES.new(key, AES.MODE_CBC) # 使用CBC模式

        encrypted_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))

        iv = cipher.iv

        return iv + encrypted_text

    # 解密

    def aes_decrypt(self, encrypted_text, key):

        iv = encrypted_text[:16]

        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_text = unpad(cipher.decrypt(encrypted_text[16:]), AES.block_size)

        return decrypted_text.decode()


    def __send(self, msg): # 不内置 json.dumps(): some objects are not hashable
        self.log.logger.debug(f"raw message to send: {msg}")
        msg_to_send = msg.encode()
        if self.encrypted_connection:
            encrypted_data = self.aes_encrypt(msg, self.aes_key) # aes_encrypt() 接受文本
            self.conn.sendall(encrypted_data)
        else:
            self.conn.sendall(msg_to_send)

    def __recv(self):
        total_data = bytes()
        while True:
            # 将收到的数据拼接起来
            data = self.conn.recv(self.BUFFER_SIZE)
            total_data += data
            if len(data) < self.BUFFER_SIZE:
                break
        if self.encrypted_connection:
            decoded = self.aes_decrypt(total_data, self.aes_key)
        else:
            decoded = total_data.decode()
        self.log.logger.debug(f"received decoded message: {decoded}")
        return decoded

    def construct_package():
        pass

    def _doFirstCommunication(self, conn):
        receive = self.__recv()
        if receive == "hello":
            self.__send("hello")
        else:
            print(receive)
            self.__send("Unknown request")
            return False
        
        if self.__recv() != "enableEncryption":
             self.__send("Unknown request")
             return False
        
        self.__send(json.dumps({
            "msg": "enableEncryption",
            "public_key": self.public_key.export_key("PEM").decode(),
            "code": 0
        }))

        receive_encrypted = conn.recv(self.BUFFER_SIZE) # 这里还不能用 self.__recv() 方法：是加密的, 无法decode()

        decrypted_data = self.pri_cipher.decrypt(receive_encrypted) # 得到AES密钥

        print(f"key: {decrypted_data}")

        self.aes_key = decrypted_data
        
        self.encrypted_connection = True # 激活加密传输标识
        
        return True

    def main(self):
        conn = self.conn # 设置别名

        es = gettext.translation("connHandler", localedir=self.root_abspath + "/content/locale", languages=[self.locale], fallback=True)
        es.install()

        if not self._doFirstCommunication(conn):
            conn.close()
            sys.exit()
        else:
            self.__send(json.dumps(
                {
                    "msg": "ok",
                    "code": 0
                }
            )) # 发送成功回答

        while True:
            try:
                recv = self.__recv()
            except ValueError: # Wrong IV, etc.
                try:
                    self.__send("?")
                except:
                    raise
                continue
            except ConnectionAbortedError or ConnectionResetError:
                print("Connection closed")
                sys.exit()

            # print(f"recv: {recv}")
            
            self.handle(recv)

    def handle(self, recv):
        self.log.logger.debug("handle() 函数被调用")
        if recv == "hello":
            self.__send("hello")
        elif (loaded_recv:=json.loads(recv))["request"] == "login":
            try:
                req_username = loaded_recv["data"].get("username", "")
                req_password = loaded_recv["data"].get("password", "")
                if (not req_username) or (not req_password):
                    raise ValueError
            except KeyError:
                self.log.logger.debug("提交的请求没有提供 data 键值")
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "invaild arguments"
                }))
                return
            except ValueError:
                self.log.logger.debug("提交的请求没有提供用户名或密码（可能 data 下对应键值为空）")
                self.__send(json.dumps({
                    "code": -2,
                    "msg": "no username or password provided"
                }))
                return
            
            self.log.logger.debug(f"收到登录请求，用户名：{req_username}，密码哈希：{req_password}") # 日志记录密码哈希其实是有泄露危险的

            self.handle_login(req_username, req_password)

        elif loaded_recv["request"] == "refreshToken":
            self.log.logger.debug("收到客户端的 refreshToken 请求")
            try:
                req_username = loaded_recv["authentication"]["username"]
                old_token = loaded_recv["authentication"]["token"]
            except KeyError:
                self.log.logger.debug("请求无效：认证数据不完整或缺失")
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "no full authentication data provided"
                }))
                return
            self.handle_refreshToken(req_username, old_token)

        elif loaded_recv["request"] == "getDocument":
            self.log.logger.debug("客户端请求调取文档")

            try:
                attached_token = loaded_recv["authentication"]["token"]
                attached_username = loaded_recv["authentication"]["username"]
            except KeyError:
                self.log.logger.debug("请求无效：认证数据不完整或缺失")
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "no full authentication data provided"
                }))
                return
            
            # 验证 token
            user = Users(attached_username, self.db_conn)

            # 读取 token_secret
            with open(f"{self.root_abspath}/content/auth/token_secret", "r") as ts_file:
                token_secret = ts_file.read()

            if not user.ifVaildToken(attached_token, token_secret):
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "invaild token or username"
                }))
                return

            self.handle_getDocument(loaded_recv, attached_username, attached_token)

        elif loaded_recv["request"] == "disconnect":
            self.__send("Goodbye")
            self.conn.close()

            self.log.logger.info("客户端断开连接")

            sys.exit() # 退出线程


            
    def handle_login(self, req_username, req_password):
        # 初始化用户对象 User()
        user = Users(req_username, self.db_conn)
        if user.ifExists():
            if user.ifMatchPassword(req_password): # actually hash
                self.log.logger.info(f"{req_username} 密码正确，准予访问")
                user.load() # 载入用户信息

                # 读取 token_secret
                with open(f"{self.root_abspath}/content/auth/token_secret", "r") as ts_file:
                    token_secret = ts_file.read()

                self.__send(json.dumps({
                    "code": 0,
                    "token": user.generateUserToken(("all"), 3600, token_secret)
                })
                )

            else:
                self.log.logger.info(f"{req_username} 密码错误，拒绝访问")

    def handle_refreshToken(self, req_username, old_token):
        user = Users(req_username, self.db_conn) # 初始化用户对象
        # 读取 token_secret
        with open(f"{self.root_abspath}/content/auth/token_secret", "r") as ts_file:
            token_secret = ts_file.read()

        if (new_token:=user.refreshUserToken(old_token, token_secret, vaild_time=3600)): # return: {token} , False
            self.__send(json.dumps(
                {
                    "code": 0,
                    "msg": "ok",
                    "token": new_token 
                }
            ))
        else:
            self.__send(json.dumps({
                "code": -1,
                "msg": "invaild token or username"
            }))

    def handle_getDocument(self, recv: dict, req_username, req_token):
        """
        a vaild request:
        {...
            "data": {
                "document_ID": "...",
                "needed_data": {...}
                }
        }
        """
        try:
            requested_document_id = recv["data"]["document_id"]
            other_needed_data = recv["data"].get("needed_data", dict())
        except KeyError:
            self.__send(json.dumps({
                "code": -1,
                "msg": "bad request"
            }))
            return

        
        doc = Documents(requested_document_id, self.db_conn)
        doc.load()

        user = Users(req_username, self.db_conn)
        if not user.ifExists():
            self.__send(json.dumps({
                "code": -1,
                "msg": "user does not exists"
            }))
            return
        
        user.load()


        if doc.if_exists:
            doc.hasUserMetRequirements(user)



                


        
            

if __name__ == "__main__":
    Thread = ConnThreads(
            target=ConnHandler, name = "threadName", args=(), kwargs={}
        )
    Thread.start()
    time.sleep(1)
    print(Thread.is_alive())