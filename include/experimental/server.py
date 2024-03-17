# from collections.abc import Callable

from functools import wraps
import gettext
import secrets
import socket
import socketserver
import json
from socketserver import BaseRequestHandler, BaseServer

import os
import sqlite3
import sys
import threading
import time
import tomllib
import traceback
import rsa
from typing import Any, Self

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from include.bulitin_class.policies import Policies
from include.bulitin_class.users import AllUsers, Users

from include.database.operator import DatabaseOperator

from include.functions import auth, optfile, optdir, optgroup, optpol
from include.logtool import getCustomLogger


class HandshakeError(Exception):
    pass


class ProgrammedSystemExit(Exception):
    """
    用于传递程序性退出的异常。
    """

    pass


class ThreadedSocketServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        server_config: dict,
        db_pool,
        bind_and_activate: bool = True,
    ) -> None:
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

        self._pool = db_pool

        self.root_abspath = os.path.abspath(
            ""
        )  # 获取当前绝对路径。根据该函数实现方法，应当返回工作目录
        self.config = server_config

        # 同样为 SocketServer 申请 logger
        self.logger = getCustomLogger(
            logname=f"main.socketserver",
            filepath=f"{self.root_abspath}/main.log",
        )

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

        sys.path.append(self.root_abspath)

        # 传输的基本设定
        self.BUFFER_SIZE = 1024

        # 设置语言
        self.locale = self.config["general"]["locale"]

        # 设置退出标志
        self.is_requested_shutdown = threading.Event()

        # 设置操作锁组
        self.locks = {"SYS_IOLOCK": threading.RLock()}

    def handle_request(self) -> None:
        return super().handle_request()

    def shutdown(self) -> None:
        self.is_requested_shutdown.set()
        return super().shutdown()

    def handle_error(self, request, client_address) -> None:

        exc_type, exc_value, exc_traceback = sys.exc_info()

        if exc_type in (ProgrammedSystemExit, HandshakeError):
            return

        if exc_type == ConnectionAbortedError:
            self.logger.info(f"{client_address}: Connection aborted")
            return
        elif exc_type == ConnectionResetError:
            self.logger.info(f"{client_address}: Connection reset")
            return

        self.logger.fatal(
            f"Exception occurred during processing of request from {client_address}:",
            exc_info=True,
        )


class SocketHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per self.requestection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    ### 定义基本响应模板

    RES_MISSING_ARGUMENT = {"code": -1, "msg": "missing necessary arguments"}

    RES_ACCESS_DENIED = {"code": 403, "msg": "access denied"}

    RES_NOT_FOUND = {"code": 404, "msg": "not found"}

    RES_INTERNAL_ERROR = {"code": 500, "msg": "internal server error"}

    RES_OK = {"code": 0, "msg": "ok"}

    RES_BAD_REQUEST = {"code": 400, "msg": "bad request"}

    RES_DUPLICATE_PACK = {"code": 400, "msg": "invaild nonce: duplicate pack?"}

    def __init__(self, request, client_address, server: ThreadedSocketServer) -> None:

        self.request = request
        self.client_address = client_address
        self.server = server

        self.config = self.server.config  # patch

        self._pool = self.server._pool

        self.all_users = AllUsers(self._pool)

        # RSA 传输相关过程
        self.pri_cipher = None
        self.pub_cipher = None

        self.private_key = None
        self.public_key = None

        # 加密传输启用标志
        self.encrypted_connection = False

        self.trace_id: str = None

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
            encrypted_data = self.aes_encrypt(
                msg, self.aes_key
            )  # aes_encrypt() 接受文本
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

    def respond(self, code, msg=None, **content):
        """
        该函数构造并发送规范的服务器响应。

        因而，使用该函数后不应再有使用 request.send() 及其他通信函数的行为。
        """

        _header = {
            "code": code,
            "msg": msg,
            "trace_id": self.trace_id,
            "api_version": "v1",
        }

        _response = dict(**_header, **content)

        self.send(json.dumps(_response))

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

        available_key_exchange_methods = ["rsa", "x25519"] # 预先定义可用的方法

        if (ukem:=config["security"]["use_key_exchange_method"]) in available_key_exchange_methods:
            if ukem == "rsa":
                self.send(
                    json.dumps(
                        {
                            "msg": "enableEncryption",
                            "method": "rsa",
                            "public_key": self.public_key.export_key("PEM").decode(),
                            "code": 0,
                        }
                    )
                )

                receive_encrypted = self.request.recv(
                    self.server.BUFFER_SIZE
                )  # 这里还不能用 self.recv() 方法：是加密的, 无法decode()

                decrypted_data = self.pri_cipher.decrypt(receive_encrypted)  # 得到AES密钥

                # self.logger.debug(f"AES Key: {decrypted_data}")

                self.aes_key = decrypted_data
                self.encrypted_connection = True
                
            elif ukem == "x25519":
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                
                with open(f"{self.server.root_abspath}/content/auth/x25519_pri", "rb") as x_pri_file:
                    x_pri_bytes = x_pri_file.read()

                x_private_key = X25519PrivateKey.from_private_bytes(x_pri_bytes)
                x_public_key = x_private_key.public_key()
                x_pub_raw = x_public_key.public_bytes_raw()

                self.send(
                    json.dumps(
                        {
                            "msg": "enableEncryption",
                            "method": "x25519",
                            "public_key": x_pub_raw,
                            "code": 0,
                        }
                    )
                )

                receive_encrypted = self.request.recv(
                    self.server.BUFFER_SIZE
                )  

                decrypted_data = self.pri_cipher.decrypt(receive_encrypted)  # 得到 private_key

                peer_public_key = X25519PublicKey.from_public_bytes(decrypted_data)

                shared_key: bytes = x_private_key.exchange(peer_public_key)

                # TODO: 实现对多种对称加密模式的支持
                
                self.aes_key = shared_key # 先用协商密钥为双向加密密钥发送新密钥
                

                self.encrypted_connection = True

                # # self.x25519_shared_
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                ).derive(shared_key)

                self.send(derived_key) # 发送导出密钥
                self.aes_key = derived_key

                try: self.recv() # 要求客户端发送有效回执
                except: raise ProgrammedSystemExit

            else:
                raise RuntimeError

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
                f"{self.client_address}: Error details for this handshake process:",
                exc_info=True,
            )
            raise HandshakeError

        self.send(json.dumps({"msg": "ok", "code": 0}))  # 发送成功回答

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

            self.trace_id = None  # 置空

            """
            X-Ca-Timestamp、X-Ca-Nonce
            """

            try:
                try:
                    recv = self.recv()
                except ValueError:  # Wrong IV, etc.
                    self.respond(**self.RES_BAD_REQUEST)
                    continue

                try:
                    loaded_recv = json.loads(recv)
                except Exception as e:
                    self.logger.debug(f"Error when loading recv: {e}")
                    self.send(json.dumps({"code": -1, "msg": "invaild request format"}))
                    continue

                client_api_version = loaded_recv.get("version", None)

                # 判断 API 版本
                if not client_api_version:
                    self.send(
                        json.dumps({"code": -1, "msg": "API version is not given"})
                    )
                    continue

                if client_api_version == 1:
                    self.handle_v1(loaded_recv)
                else:  # 目前仅支持 V1
                    self.send(
                        json.dumps({"code": -1, "msg": "unsupported API version"})
                    )
                    continue

            except (ConnectionAbortedError, ConnectionResetError):
                raise
            except TimeoutError:
                self.logger.info(
                    f"{self.client_address}: Connection timed out. Disconnecting."
                )
                return
            except:

                exc_log_id = self.trace_id if self.trace_id else secrets.token_hex(8)

                self.logger.error(
                    f"[{exc_log_id}] Error occurred when handling the request of {self.client_address}:",
                    exc_info=True,
                )

                e_type, e_value, e_traceback = sys.exc_info()
                self.respond(
                    500,
                    msg="Internal Server Error",
                    exc_info={
                        "exc_id": exc_log_id,  # self.trace_id if exists, else a randomized 8-letter string
                        "exc_type": str(e_type),
                        "exc_value": (
                            str(e_value)
                            if self.server.config["debug"]["show_exc_details"]
                            else None
                        ),
                        "exc_traceback": (
                            traceback.format_exc()
                            if self.server.config["debug"]["show_exc_details"]
                            else None
                        ),
                    },
                )

                del exc_log_id, e_traceback, e_type, e_value
                continue
            # print(f"recv: {recv}")

        # 当跳出上述循环，即代表处理过程终止

        self.logger.debug(
            f"终止信号被激活，正在终止处理连接 {self.client_address} 的操作..."
        )

        return
        # self.logger.debug("正在终止与客户端和数据库的连接...")

        # self.db_conn.close()

    def filterPathProperties(self, properties: dict):
        result = properties

        # TODO #11

        return result

    def _getNewestRevisionID(self, path_id) -> str | None:

        with DatabaseOperator(self._pool) as couple:
            handle_cursor = couple[1]

            handle_cursor.execute(
                "SELECT `revisions` FROM path_structures WHERE `id` = ?", (path_id,)
            )
            query_result = handle_cursor.fetchall()

            if len(query_result) != 1:  # 由于主键互异性，可知其代表不存在
                raise ValueError("Specified ID does not exist")
                # 这可能代表一种情况：数据库在操作的间隙间发生了变动。

            # 查询文档下的所有历史版本
            query_revisions: dict = json.loads(query_result[0][0])

            newest_revision = ()  # by default

            # 排序
            sorted_revisions: list = sorted(
                query_revisions.items(), key=lambda i: i[1]["time"], reverse=True
            )

            # 如果已经删除
            for per_revision in sorted_revisions:  # per_revision is a tuple
                if (
                    per_revision[1]["state"]["code"] == "deleted"
                ):  # 我们假定用户希望得到最新的版本是未被删除的
                    continue
                # 指定 newest
                newest_revision = per_revision
                break

            return newest_revision[0] if newest_revision else None  # 指定

    def _hasFileRecord(self, file_id):  # path_structures

        with DatabaseOperator(self._pool) as couple:

            couple[1].execute(
                "SELECT name FROM path_structures WHERE id = ?", (file_id,)
            )
            _result = couple[1].fetchall()

            _len = len(_result)

            if _len == 1:
                return _result[0][0]
            elif _len == 0:
                return False
            else:
                raise RuntimeError("Wrong result length")

    def getFileSize(self, path_id, rev_id=None):

        with DatabaseOperator(self._pool) as couple:

            # g_cur = self.db_cursor

            couple[1].execute(
                "SELECT `type`, `revisions` FROM path_structures WHERE `id` = ?",
                (path_id,),
            )

            query_result = couple[1].fetchall()

            if len(query_result) == 0:
                raise FileNotFoundError
            elif len(query_result) > 1:
                raise RuntimeError(
                    "在执行 getFileSize 操作时发现数据库出现相同ID的多条记录"
                )

            this_file_result = query_result[0]

            if this_file_result[0] != "file":
                raise TypeError

            if not rev_id:
                rev_id = self._getNewestRevisionID(path_id)
                if (
                    not rev_id
                ):  # 如果自动获取了ID却仍然为空（代表没有满足条件的结果），则不计算大小
                    return -1

            # index_file_id = this_file_result[1]
            got_revisions = json.loads(this_file_result[1])

            if rev_id not in got_revisions:
                raise ValueError("Revision ID not found")

            this_rev_file_id = got_revisions[rev_id]["file_id"]

            if not this_rev_file_id:
                raise RuntimeError("意料外的数据库记录")

            del this_file_result, query_result  # 清除

            couple[1].execute(
                "SELECT `path` FROM document_indexes WHERE `id` = ?",
                (this_rev_file_id,),
            )

            query_result = couple[1].fetchall()

            if len(query_result) == 0:
                raise FileNotFoundError("在 document_indexes 表中未发现对应的数据")
            elif len(query_result) > 1:
                raise RuntimeError(
                    "在执行 getFileSize 操作时发现数据库出现相同ID的多条记录"
                )

            this_real_file_result = query_result[0]

            # cleanup
            # g_cur.close()

            if self.server.locks["SYS_IOLOCK"].acquire(timeout=0.75):
                filesize = os.path.getsize(
                    self.server.root_abspath + this_real_file_result[0]
                )
                self.server.locks["SYS_IOLOCK"].release()
                return filesize
            else:  # 如果超时
                return -1

    def _verifyAccess(
        self,
        user: Users,
        action,
        access_rules: dict,
        external_access: dict,
        check_deny=True,
    ):
        if not access_rules:  # fix #7
            return True  # fallback

        # print(access_rules)

        if "super_access" in user.rights:
            return True  # 放行超级权限，避免管理员被锁定在外

        # 确认是否满足 deny 规则
        if check_deny:
            # print(access_rules)
            # print()
            all_deny_rules = access_rules.get("deny", {})

            this_action_deny_value = all_deny_rules.get(action, {})

            # print(this_action_deny_value)
            this_deny_groups = this_action_deny_value.get("groups", {})
            this_deny_users = this_action_deny_value.get("users", {})
            this_deny_rules = this_action_deny_value.get("rules", [])

            _deny_expire_time = None  # 置空

            if user.username in this_deny_users:
                if not (
                    _deny_expire_time := this_deny_users[user.username].get("expire", 0)
                ):  # 如果expire为0
                    return False
                if _deny_expire_time > time.time():  # 如果尚未过期
                    return False

            _deny_expire_time = None  # 置空

            for i in user.groups:
                if i in this_deny_groups:
                    if not (
                        _deny_expire_time := this_deny_groups[i].get("expire", 0)
                    ):  # 如果expire为0
                        return False
                    if _deny_expire_time > time.time():  # 如果尚未过期
                        return False

            del _deny_expire_time

            if this_deny_rules:  # 必须存在才会判断
                if user.ifMatchRules(this_deny_rules):
                    return False

        # access_rules 包括所有规则
        if user.ifMatchRules(access_rules.get(action, [])):
            return True

        if external_access:
            for i in external_access["groups"]:
                if action not in (i_dict := external_access["groups"][i]).keys():
                    continue
                if (not (expire_time := i_dict[action].get("expire", 0))) or (
                    expire_time >= time.time()
                ):  # 如果用户组拥有的权限尚未到期
                    if i in user.groups:  # 如果用户存在于此用户组
                        return True

            if (
                user.username in external_access["users"].keys()
            ):  # 如果用户在字典中有记录
                if (
                    action
                    in (
                        user_action_dict := external_access["users"][user.username]
                    ).keys()
                ):  # 如果请求操作在用户的字典中有记录
                    if (
                        not (expire_time := user_action_dict[action].get("expire", 0))
                    ) or (
                        expire_time >= time.time()
                    ):  # 如果用户拥有的权限尚未到期
                        return True

        return False

    def verifyUserAccess(
        self,
        id,
        action,
        user: Users,
        checkdeny=True,
        _subcall=False,
        dboptr: DatabaseOperator = None,
    ):
        """
        用户鉴权函数。
        用于逐级检查用户是否拥有 **文件或文件夹的** 访问权限，若发生任意不满足条件的情况即返回 False
        """

        # print(self.db_cursor._connection)
        if not dboptr:
            dboptr = DatabaseOperator(self._pool)

        por_policy = Policies("permission_on_rootdir", *dboptr)

        if id == None:
            raise ValueError
        elif not id:
            self.logger.debug("请求验证的路径是根目录")

            por_access_rules = por_policy["rules"]["access_rules"]
            por_external_access = por_policy["rules"]["external_access"]

            if not self._verifyAccess(
                user, action, por_access_rules, por_external_access, checkdeny
            ):
                self.logger.debug("PoR 鉴权失败")
                return False
            else:
                self.logger.debug("PoR 鉴权成功")
                return True

        self.logger.debug(
            f"verifyUserAccess(): 正在对 用户 {user.username} 访问 id: {id} 的请求 进行鉴权"
        )

        db_cur = dboptr[1]

        db_cur.execute(
            "SELECT `parent_id`, `access_rules`, `external_access`, `type` FROM path_structures WHERE `id` = ?",
            (id,),
        )

        result = db_cur.fetchall()

        # assert len(result) == 1
        if _ := len(result) != 1:
            if _ == 0:
                raise FileNotFoundError
            else:
                raise RuntimeError("Expected less than 2 results, got more")

        access_rules = json.loads(result[0][1])
        external_access = json.loads(result[0][2])

        if _subcall:  # 如果来自子路径调用（这应该表示本路径是一个文件夹）
            self.logger.debug("_subcall 为真")

            if result[0][3] != "dir":
                raise TypeError("Not a directory: does not support _subcall")

            if not access_rules.get(
                "__subinherit__", True
            ):  # 如果设置为下层不继承（对于文件应该无此设置）
                self.logger.debug("本层设置为下层不继承，返回为真")
                return True

        if not (
            action in (_noinherit := access_rules.get("__noinherit__", []))
        ) and not (
            "all" in _noinherit
        ):  # 判断该目录是否继承上层设置
            if (
                not (f"deny_{action}" in (_noinherit))
                and (not "deny" in _noinherit)
                and checkdeny
            ):
                # 1. 本层路径继承上层设置；
                # 2. 本函数的调用者要求检查 deny；
                self.logger.debug("将检查上级目录的 deny 规则")
                parent_checkdeny = True
            else:
                parent_checkdeny = False

            if parent := result[0][0]:  # 如果仍有父级
                self.logger.debug(f"正在检查其父目录 {parent} 的权限...")
                if not self.verifyUserAccess(
                    parent, action, user, checkdeny=parent_checkdeny, _subcall=True
                ):
                    return False
                self.logger.debug("完毕，无事发生。")

            elif por_policy["inherit_by_subdirectory"]:  # 如果没有父级（是根目录）
                if not self.verifyUserAccess(
                    "", action, user, parent_checkdeny, True, dboptr
                ):
                    return False

        else:
            self.logger.debug("请求操作在该路径上被设置为不继承上层设置，跳过")

        self.logger.debug(
            f"所有访问规则和附加权限记录：{access_rules}, {external_access}"
        )

        if self._verifyAccess(
            user, action, access_rules, external_access, check_deny=checkdeny
        ):
            self.logger.debug(
                f"verifyUserAccess(): 用户 {user.username} 对于 id: {id} 的请求 鉴权成功"
            )
            return True

        self.logger.debug("校验失败。")
        return False

    def handle_v1(self, loaded_recv):
        """
        实际处理符合 API v1 规范的入口函数。

        该函数通过调用拆分至各个模块的以实例自身为第一参数的分函数进行请求的处理。
        """

        # from include.experimental.api_v1 import auth

        self.logger.debug("handle_v1() 函数被调用")

        if "trace_id" in loaded_recv:
            self.trace_id = loaded_recv["trace_id"]  # 准备合并

        # Replay attack fix
        if not self.trace_id:
            self.respond(**self.RES_BAD_REQUEST)
            return

        try:
            request_timestamp: float = loaded_recv["X-Ca-Timestamp"]
        except KeyError:
            self.respond(400, msg="X-Ca-Timestamp is not provided")
            return

        if (time.time() - 300 > request_timestamp) or (
            time.time() + 300 < request_timestamp
        ):  # +-300 秒误差范围
            self.respond(400, msg="X-Ca-Timestamp out of allowed range")
            return

        if config["database"]["use_cache_engine"] == "sqlite3":
            s_db = sqlite3.connect(self.server.root_abspath + "/security.db")
            

        # if request_nonce in used_nonces:
        #     pass

        if loaded_recv["request"] == "login":
            try:
                req_username = loaded_recv["data"].get("username", "")
                req_password = loaded_recv["data"].get("password", "")
                if (not req_username) or (not req_password):
                    raise ValueError
            except KeyError:
                self.logger.debug("提交的请求没有提供 data 键值")
                self.respond(-1, msg="invaild arguments")
                return
            except ValueError:
                self.logger.debug(
                    "提交的请求没有提供用户名或密码（可能 data 下对应键值为空）"
                )
                self.respond(-2, msg="no username or password provided")
                return

            self.logger.debug(
                f"收到登录请求，用户名：{req_username}，密码哈希：{req_password}"
            )  # 日志记录密码哈希其实是有泄露危险的

            self.handle_login(req_username, req_password)
            # auth.handle_login(self, req_username, req_password)

            return  # 如果不返回，那么下面的判断就会被执行了

        elif loaded_recv["request"] == "disconnect":
            try:
                self.send("Goodbye")
            except ConnectionResetError:  # 客户端此时断开了也无所谓
                pass

            self.logger.info(f"{self.client_address}: 客户端断开连接")

            # sys.exit()  # 退出线程

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
            self.send(
                json.dumps({"code": -1, "msg": "no full authentication data provided"})
            )
            return

        ### 结束

        # 定义了支持的所有请求类型。
        available_requests = {
            "refreshToken": auth.handle_refreshToken,
            "operateFile": optfile.handle_operateFile,
            "operateDir": optdir.handle_operateDir,
            "operateUser": auth.handle_operateUser,
            "getRootDir": optdir.handle_getRootDir,
            "getPolicy": optpol.handle_getPolicy,
            "getAvatar": auth.handle_getAvatar,
            "createFile": optfile.handle_createFile,
            "createUser": auth.handle_createUser,
            "createDir": optdir.handle_createDir,
            "createGroup": optgroup.handle_createGroup,
            "getUserProperties": auth.handle_getUserProperties,
            "getFileRevisions": optfile.handle_getFileRevisions,
            "shutdown": self.handle_shutdown,
            # "emergency": None
        }

        for i in self.server.config["security"]["disabled_functions"]:
            del available_requests[i]

        # 定义了需要传入 Users 对象的函数列表。用于判断使用。
        # External User Objects
        outfile_requests = (
            "operateFile",
            "operateDir",
            "getRootDir",
            "operateUser",
            "getPolicy",
            "getAvatar",
            "createFile",
            "createUser",
            "createDir",
            "createGroup",
            "getUserProperties",
            "getFileRevisions",
        )

        excluded_requests = ("refreshToken",)

        given_request = loaded_recv["request"]

        if given_request in available_requests:
            if given_request in outfile_requests:

                user = self.all_users[self.this_time_username]

                # 读取 token_secret
                with open(
                    f"{self.server.root_abspath}/content/auth/token_secret", "r"
                ) as ts_file:
                    token_secret = ts_file.read()

                if not user.isVaildToken(self.this_time_token, token_secret):
                    self.respond(**{"code": -1, "msg": "invaild token or username"})
                    return

                available_requests[given_request](self, loaded_recv, user=user)

                ### 结束

                del user

            else:
                if given_request in excluded_requests:
                    available_requests[given_request](self, loaded_recv)
                else:
                    available_requests[given_request](loaded_recv)
        else:
            self.respond(-1, msg="unknown request")

        # 收尾
        self.this_time_token = None
        self.this_time_username = None  # 置空

    def handle_login(self, req_username, req_password):

        # 初始化用户对象 User()
        with DatabaseOperator(self._pool) as couple:

            if req_username in self.all_users:

                user = self.all_users[req_username]

                if user.isMatchPassword(req_password):  # actually hash
                    self.logger.info(f"{req_username} 密码正确，准予访问")

                    # 读取 token_secret
                    with open(
                        f"{self.server.root_abspath}/content/auth/token_secret", "r"
                    ) as ts_file:
                        token_secret = ts_file.read()

                    self.respond(
                        0,
                        token=user.generateUserToken(("all"), 3600, token_secret),
                        ftp_port=self.server.config["connect"]["ftp_port"],
                    )

                else:
                    self.logger.info(f"{req_username} 密码错误，拒绝访问")

                    user_auth_policy = Policies("user_auth", *couple)
                    sleep_for_fail = user_auth_policy["sleep_when_login_fail"]

                    if sleep_for_fail:
                        self.logger.debug(f"正根据登录策略睡眠 {sleep_for_fail} 秒")
                        time.sleep(sleep_for_fail)

                    if self.server.config["security"]["show_login_fail_details"]:
                        fail_msg = "password incorrect"
                    else:
                        fail_msg = "username or password incorrect"

                    self.respond(401, msg=fail_msg)
            else:
                if self.server.config["security"]["show_login_fail_details"]:
                    fail_msg = "user does not exist"
                else:
                    fail_msg = "username or password incorrect"

                user_auth_policy = Policies("user_auth", *couple)
                sleep_for_fail = user_auth_policy["sleep_when_login_fail"]

                if sleep_for_fail:
                    self.logger.debug(f"正根据登录策略睡眠 {sleep_for_fail} 秒")
                    time.sleep(sleep_for_fail)

                self.respond(401, msg=fail_msg)

    # @staticmethod
    def userOperationAuthWrapper(func):
        @wraps(func)
        def _wrapper(self: Self, *args, **kwargs):
            ### 通用用户令牌鉴权开始

            # 验证 token

            user = self.all_users[self.this_time_username]

            # 读取 token_secret
            with open(
                f"{self.server.root_abspath}/content/auth/token_secret", "r"
            ) as ts_file:
                token_secret = ts_file.read()

            if not user.isVaildToken(self.this_time_token, token_secret):
                self.respond(**{"code": -1, "msg": "invaild token or username"})
                return

            ### 结束

            func(self, *args, **kwargs, user=user)  # 仅当上述操作成功该函数才会被执行

        return _wrapper

    @userOperationAuthWrapper
    def handle_shutdown(self, loaded_recv, user: Users):
        if not "shutdown" in user.rights:
            self.respond(**self.RES_ACCESS_DENIED)
            return

        self.server.shutdown()

        self.respond(**{"code": 200, "msg": "goodbye"})

        return


if __name__ == "__main__":

    HOST, PORT = "localhost", 9999

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    # Create the server, binding to localhost on port 9999
    with ThreadedSocketServer(
        (HOST, PORT), SocketHandler, server_config=config
    ) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
