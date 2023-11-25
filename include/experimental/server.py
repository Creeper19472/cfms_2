
# from collections.abc import Callable

import gettext
import socketserver
import json
from socketserver import BaseRequestHandler, BaseServer

import os
import sys
import threading
import time
import tomllib
import rsa
from typing import Any, Self

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from include.bulitin_class.policies import Policies

from include.bulitin_class.users import Users

class HandshakeError(Exception):
    pass

class ProgrammedSystemExit(Exception):
    """
    用于传递程序性退出的异常。
    """
    pass

class ThreadedSocketServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, server_config: dict, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

        self.root_abspath = os.path.abspath("") # 获取当前绝对路径。根据该函数实现方法，应当返回工作目录
        self.config = server_config

        sys.path.append(self.root_abspath)

        # 传输的基本设定
        self.BUFFER_SIZE = 1024

        # 设置语言
        self.locale = self.config["general"]["locale"]

        # 设置退出标志
        self.is_requested_shutdown = threading.Event()

    def handle_request(self) -> None:
        return super().handle_request()

    def shutdown(self) -> None:
        self.is_requested_shutdown.set()
        return super().shutdown()
    
    def handle_error(self, request, client_address) -> None:
        
        exc_type, exc_value, exc_traceback = sys.exc_info()

        if exc_type in (ProgrammedSystemExit, HandshakeError):
            return
        
        return super().handle_error(request, client_address)
    


class SocketHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per self.requestection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def __init__(self, request, client_address, server: ThreadedSocketServer) -> None:

        self.request = request
        self.client_address = client_address
        self.server = server

        # RSA 传输相关过程
        self.pri_cipher = None
        self.pub_cipher = None

        self.private_key = None
        self.public_key = None

        # 加密传输启用标志
        self.encrypted_connection = False

        from include.logtool import getCustomLogger

        self.logger = getCustomLogger(
            logname=f"main.connHandler.{client_address}",
            filepath=f"{server.root_abspath}/main.log",
        )

        self.setup()
        
        try:
            self.handle()
        finally:
            self.finish()
        
        # super().__init__(request, client_address, server)
        

    def send(self, msg):  # 不内置 json.dumps(): some objects are not hashable
        self.logger.debug(f"raw message to send: {msg}")
        msg_to_send = msg.encode()
        if self.encrypted_connection:
            encrypted_data = self.aes_encrypt(msg, self.aes_key)  # aes_encrypt() 接受文本
            self.request.sendall(encrypted_data)
        else:
            self.request.sendall(msg_to_send)

    def recv(self):
        total_data = bytes()
        while True:
            # 将收到的数据拼接起来
            data = self.request.recv(self.server.BUFFER_SIZE)
            total_data += data
            if len(data) < self.server.BUFFER_SIZE:
                break
        if self.encrypted_connection:
            decoded = self.aes_decrypt(total_data, self.aes_key)
        else:
            decoded = total_data.decode()
        self.logger.debug(f"received decoded message: {decoded}")
        return decoded
    



    def _setup_handshake(self) -> None:
        # self.request.settimeout(10.0) # 设置超时
        try:
            receive = self.recv()
        except TimeoutError:
            raise
        if receive == "hello":
            self.send("hello")
        elif "HTTP/1." in receive:
            self.logger.debug("客户端试图以HTTP协议进行通信。这并非所支持的。")
            self.logger.info(f"{self.client_address}: Handshake failed: HTTP request.")

            with open(f"{self.server.root_abspath}/content/418.html") as f:
                html_content = f.read()

            response = f"""HTTP/1.1 418 I'm a teapot
            Server: CFMS Server
            Accept-Ranges: bytes
            Vary: Accept-Encoding
            Content-Type: text/plain

            {html_content}

            """
            self.send(response)
            raise ProgrammedSystemExit

        else:
            self.logger.debug(f"客户端发送了意料之外的请求：\n{receive}")
            self.send("Unknown request")
            raise ProgrammedSystemExit

        if self.recv() != "enableEncryption":
            self.send("Unknown request")
            raise ProgrammedSystemExit

        self.send(
            json.dumps(
                {
                    "msg": "enableEncryption",
                    "public_key": self.public_key.export_key("PEM").decode(),
                    "code": 0,
                }
            )
        )

        receive_encrypted = self.request.recv(
            self.server.BUFFER_SIZE
        )  # 这里还不能用 self.recv() 方法：是加密的, 无法decode()

        decrypted_data = self.pri_cipher.decrypt(receive_encrypted)  # 得到AES密钥

        self.logger.debug(f"AES Key: {decrypted_data}")

        self.aes_key = decrypted_data

        self.encrypted_connection = True

        return

    def setup(self) -> None:
        """
        该函数负责完成对传输的初始化设置，设立必要的加密过程。
        如果在该握手过程中失败，将抛出错误。
        """

        # 初始化 RSA 操作子
        with open(f"{self.server.root_abspath}/content/auth/pri.pem", "rb") as pri_file:
            self.private_key = RSA.import_key(pri_file.read())
        self.pri_cipher = PKCS1_OAEP.new(self.private_key)

        with open(f"{self.server.root_abspath}/content/auth/pub.pem", "rb") as pub_file:
            self.public_key = RSA.import_key(pub_file.read())
        self.pub_cipher = PKCS1_OAEP.new(self.public_key)

        # 执行握手过程

        es = gettext.translation(
            "connHandler",
            localedir=self.server.root_abspath + "/content/locale",
            languages=[self.server.locale],
            fallback=True,
        )
        es.install()

        try:
            self._setup_handshake()
        except ProgrammedSystemExit:
            raise
        except:
            self.logger.info(f"{self.client_address}: Handshake failed.")
            self.logger.info(
                f"{self.client_address}: Error details for this handshake process:", exc_info=True
            )
            raise HandshakeError

        self.__send(json.dumps({"msg": "ok", "code": 0}))  # 发送成功回答

        return
    
    def finish(self):
        return super().finish()

    def aes_encrypt(self, plain_text, key):
        cipher = AES.new(key, AES.MODE_CBC)  # 使用CBC模式

        encrypted_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))

        iv = cipher.iv

        return iv + encrypted_text

    # 解密

    def aes_decrypt(self, encrypted_text, key):
        iv = encrypted_text[:16]

        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_text = unpad(cipher.decrypt(encrypted_text[16:]), AES.block_size)

        return decrypted_text.decode()

    def handle(self):

        while not self.server.is_requested_shutdown.is_set():
            # self.server.shutdown_request()

            try:
                recv = self.recv()
            except ValueError:  # Wrong IV, etc.
                try:
                    self.send("?")
                except:
                    raise
                continue
            except ConnectionAbortedError:
                self.logger.info(f"{self.client_address}: Connection aborted")
                return
            except ConnectionResetError:
                self.logger.info(f"{self.client_address}: Connection reset")
                return
            except TimeoutError:
                self.logger.info(
                    f"{self.client_address}: Connection timed out. Disconnecting."
                )
                return
            # print(f"recv: {recv}")

            try:
                loaded_recv = json.loads(recv)
            except Exception as e:
                self.logger.debug(f"Error when loading recv: {e}")
                self.send(json.dumps({"code": -1, "msg": "invaild request format"}))
                continue

            client_api_version = loaded_recv.get("version", None)

            # 判断 API 版本
            if not client_api_version:
                self.send(json.dumps({"code": -1, "msg": "API version is not given"}))
                continue

            if client_api_version == 1:
                self.handle_v1(loaded_recv)
            else:  # 目前仅支持 V1
                self.send(json.dumps({"code": -1, "msg": "unsupported API version"}))
                continue

        # 当跳出上述循环，即代表处理过程终止
        
        self.logger.debug(f"终止信号被激活，正在终止处理连接 {self.client_address} 的操作...")

        return
        # self.logger.debug("正在终止与客户端和数据库的连接...")
        
        # self.db_conn.close()

    def handle_v1(self, loaded_recv):
        """
        实际处理符合 API v1 规范的入口函数。
        
        该函数通过调用拆分至各个模块的以实例自身为第一参数的分函数进行请求的处理。
        """

        # from include.experimental.api_v1 import auth

        self.logger.debug("handle_v1() 函数被调用")

        if loaded_recv["request"] == "login":
            try:
                req_username = loaded_recv["data"].get("username", "")
                req_password = loaded_recv["data"].get("password", "")
                if (not req_username) or (not req_password):
                    raise ValueError
            except KeyError:
                self.logger.debug("提交的请求没有提供 data 键值")
                self.__send(json.dumps({"code": -1, "msg": "invaild arguments"}))
                return
            except ValueError:
                self.logger.debug("提交的请求没有提供用户名或密码（可能 data 下对应键值为空）")
                self.__send(
                    json.dumps({"code": -2, "msg": "no username or password provided"})
                )
                return

            self.logger.debug(
                f"收到登录请求，用户名：{req_username}，密码哈希：{req_password}"
            )  # 日志记录密码哈希其实是有泄露危险的

            self.handle_login(req_username, req_password)
            # auth.handle_login(self, req_username, req_password)

            return  # 如果不返回，那么下面的判断就会被执行了

        elif loaded_recv["request"] == "disconnect":
            try:
                self.__send("Goodbye")
            except ConnectionResetError:  # 客户端此时断开了也无所谓
                pass
            finally:
                self.conn.close()

            self.logger.info(f"{self.addr}: 客户端断开连接")

            sys.exit()  # 退出线程

        # 以下的所有请求都应该是需要鉴权的，如果不是请放在上面
        # 如果需要与以下鉴权过程不同的鉴权请放在上面处理
        # 上面部分的每个判断都应该有 return

        ### 获取 auth 标头

        try:
            attached_token = loaded_recv["auth"]["token"]
            attached_username = loaded_recv["auth"]["username"]
            self.this_time_token = attached_token
            self.this_time_username = attached_username
        except KeyError:
            self.logger.debug("请求无效：认证数据不完整或缺失")
            self.__send(
                json.dumps({"code": -1, "msg": "no full authentication data provided"})
            )
            return

        ### 结束

        # 定义了支持的所有请求类型。
        available_requests = {
            # "refreshToken": auth.handle_refreshToken,
            "refreshToken": self.handle_refreshToken,
            "operateFile": self.handle_operateFile,
            "operateDir": self.handle_operateDir,
            "operateUser": self.handle_operateUser,
            "getRootDir": self.handle_getRootDir,
            "getPolicy": self.handle_getPolicy,
            "getAvatar": self.handle_getAvatar, 
            "createFile": self.handle_createFile,
            "createUser": self.handle_createUser,
            "createDir": self.handle_createDir,
            "createGroup": self.handle_createGroup,
            "getUserProperties": self.handle_getUserProperties,
            "getFileRevisions": self.handle_getFileRevisions,
            "shutdown": self.handle_shutdown,
        }

        given_request = loaded_recv["request"]

        if given_request in available_requests:
            available_requests[given_request](loaded_recv)
        else:
            self.__send(json.dumps({"code": -1, "msg": "unknown request"}))

        # 收尾
        self.this_time_token = None
        self.this_time_username = None  # 置空

    def handle_login(self, req_username, req_password):
        # 初始化用户对象 User()
        user = Users(req_username, self.db_conn, self.db_cursor)
        if user.ifExists():
            if user.ifMatchPassword(req_password):  # actually hash
                self.logger.info(f"{req_username} 密码正确，准予访问")
                user.load()  # 载入用户信息

                # 读取 token_secret
                with open(
                    f"{self.root_abspath}/content/auth/token_secret", "r"
                ) as ts_file:
                    token_secret = ts_file.read()

                self.__send(
                    json.dumps(
                        {
                            "code": 0,
                            "token": user.generateUserToken(
                                ("all"), 3600, token_secret
                            ),
                            "ftp_port": self.config["connect"]["ftp_port"],
                        }
                    )
                )

            else:
                self.logger.info(f"{req_username} 密码错误，拒绝访问")

                user_auth_policy = Policies("user_auth", self.db_conn, self.db_cursor)
                sleep_for_fail = user_auth_policy["sleep_when_login_fail"]

                if sleep_for_fail:
                    self.logger.debug(f"正根据登录策略睡眠 {sleep_for_fail} 秒")
                    time.sleep(sleep_for_fail)

                if self.config["security"]["show_login_fail_details"]:
                    fail_msg = "password incorrect"
                else:
                    fail_msg = "username or password incorrect"

                self.__send(json.dumps({"code": 401, "msg": fail_msg}))
        else:
            if self.config["security"]["show_login_fail_details"]:
                fail_msg = "user does not exist"
            else:
                fail_msg = "username or password incorrect"

            user_auth_policy = Policies("user_auth", self.db_conn, self.db_cursor)
            sleep_for_fail = user_auth_policy["sleep_when_login_fail"]

            if sleep_for_fail:
                self.logger.debug(f"正根据登录策略睡眠 {sleep_for_fail} 秒")
                time.sleep(sleep_for_fail)

            self.__send(json.dumps({"code": 401, "msg": fail_msg}))

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    # Create the server, binding to localhost on port 9999
    with ThreadedSocketServer((HOST, PORT), SocketHandler, server_config=config) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()