# connThread.py
# No longer in use and is no logger supported. Will be removed in future versions but
# still in the place for now for historical references.

from functools import wraps
import os
import datetime
import secrets
import hashlib
import socket
import string
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
from include.bulitin_class._documents import Documents  # 已弃用
from include.bulitin_class.policies import Policies

from include.util.structurecheck import StructureValidater
from include.util.convert import convertFile2PathID

from include.database.abstracted import getDBConnection

from dbutils.persistent_db import PersistentDB
from mysql.connector.pooling import MySQLConnectionPool
from mysql.connector.pooling import PooledMySQLConnection

from typing import Iterable, Self

import uuid


class PendingWriteFileError(Exception):
    pass


class ConnThreads(threading.Thread):
    def __init__(
        self, target, name, semaphore: threading.Semaphore, args=(), kwargs={}
    ):
        super().__init__()
        self.target = target
        self.name = name  # 只能是这个变量名
        # 传给真正的处理类
        self.args = args
        self.kwargs = kwargs

        self.semaphore = semaphore

    def run(self):
        with self.semaphore:
            target_class = self.target(self.name, *self.args, **self.kwargs)

            try:
                target_class.main()
            except ConnectionResetError:
                target_class.log.logger.info(f"{self.name}: Connection reset")
                sys.exit()
            except Exception as e:
                e.add_note("看起来线程内部的运行出现了问题。将关闭到客户端的连接。")
                target_class.log.logger.fatal(
                    f"{self.name}: 看起来线程内部的运行出现了问题：", exc_info=True
                )
                target_class.conn.close()

            target_class.db_conn.close()
            sys.exit()


class ConnHandler:
    # 定义经常使用的响应内容

    RES_MISSING_ARGUMENT = {"code": -1, "msg": "missing necessary arguments"}

    RES_ACCESS_DENIED = {"code": 403, "msg": "access denied"}

    RES_NOT_FOUND = {"code": 404, "msg": "not found"}

    RES_INTERNAL_ERROR = {"code": 500, "msg": "internal server error"}

    RES_OK = {"code": 0, "msg": "ok"}

    RES_BAD_REQUEST = {"code": 400, "msg": "bad request"}

    def __init__(
        self, thread_name, *args, **kwargs
    ):  #!!注意，self.thread_name 在调用类定义！
        self.root_abspath = kwargs["root_abspath"]

        self.args = args
        self.kwargs = kwargs
        self.thread_name = thread_name

        self.terminate_event = kwargs["threading.terminate_event"]

        global SYS_LOCKS
        SYS_LOCKS = kwargs["sys_locks"]

        self.conn = kwargs["conn"]
        self.addr = kwargs["addr"]

        # 用于装饰器
        self.this_time_token = None
        self.this_time_username = None

        self.config = kwargs["toml_config"]  # 导入配置字典

        # 获取连接池
        self.db_pool: MySQLConnectionPool | PersistentDB = kwargs["db_pool"]

        self.db_conn = getDBConnection(self.db_pool)  # 这仅开启主数据库的连接

        # 获取单一游标对象，准备采取一线程一连接一游标的模式
        # print(isinstance(self.db_conn, PooledMySQLConnection))
        if isinstance(self.db_conn, PooledMySQLConnection):
            self.db_cursor = self.db_conn._cnx.cursor(prepared=True)
        else:
            self.db_cursor = self.db_conn.cursor()

        # print(self.db_cursor._connection)

        self.locale = self.config["general"]["locale"]

        sys.path.append(f"{self.root_abspath}/include/")  # 增加导入位置
        # sys.path.append(f"{self.root_abspath}/include/class")

        from logtool import LogClass

        self.log = LogClass(
            logname=f"main.connHandler.{self.thread_name}",
            filepath=f"{self.root_abspath}/main.log",
        )

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

    def __send(self, msg):  # 不内置 json.dumps(): some objects are not hashable
        self.log.logger.debug(f"raw message to send: {msg}")
        msg_to_send = msg.encode()
        if self.encrypted_connection:
            encrypted_data = self.aes_encrypt(
                msg, self.aes_key
            )  # aes_encrypt() 接受文本
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

    def _doFirstCommunication(self, conn):
        receive = self.__recv()
        if receive == "hello":
            self.__send("hello")
        elif "HTTP/1." in receive:
            self.log.logger.debug("客户端试图以HTTP协议进行通信。这并非所支持的。")

            with open(f"{self.root_abspath}/content/418.html") as f:
                html_content = f.read()

            response = f"""HTTP/1.1 418 I'm a teapot
            Server: CFMS Server
            Accept-Ranges: bytes
            Vary: Accept-Encoding
            Content-Type: text/plain

            {html_content}

            """
            self.__send(response)
            return False

        else:
            self.log.logger.debug(f"客户端发送了意料之外的请求：\n{receive}")
            self.__send("Unknown request")
            return False

        if self.__recv() != "enableEncryption":
            self.__send("Unknown request")
            return False

        self.__send(
            json.dumps(
                {
                    "msg": "enableEncryption",
                    "public_key": self.public_key.export_key("PEM").decode(),
                    "code": 0,
                }
            )
        )

        receive_encrypted = conn.recv(
            self.BUFFER_SIZE
        )  # 这里还不能用 self.__recv() 方法：是加密的, 无法decode()

        decrypted_data = self.pri_cipher.decrypt(receive_encrypted)  # 得到AES密钥

        self.log.logger.debug(f"AES Key: {decrypted_data}")

        self.aes_key = decrypted_data

        self.encrypted_connection = True  # 激活加密传输标识

        return True

    def _createFileIndex(self, new_index_id: str | None = None):
        handle_cursor = self.db_cursor

        # 开始创建文件

        index_file_id = (
            new_index_id if new_index_id else secrets.token_hex(64)
        )  # 存储在 document_indexes 中
        real_filename = secrets.token_hex(16)

        today = datetime.date.today()

        destination_path = (
            f"{self.root_abspath}/content/files/{today.year}/{today.month}"
        )

        os.makedirs(destination_path, exist_ok=True)  # 即使文件夹已存在也加以继续

        with open(f"{destination_path}/{real_filename}", "w") as new_file:
            pass

        # 注册数据库条目

        # handle_cursor.execute("BEGIN TRANSACTION;")

        handle_cursor.execute(
            "INSERT INTO document_indexes (`id`, `abspath`) VALUES (?, ?)",
            (index_file_id, destination_path + "/" + real_filename),
        )

        # handle_cursor.execute("COMMIT TRANSACTION;")
        self.db_conn.commit()

        return index_file_id

    def _getNewestRevisionID(self, path_id) -> str | None:
        handle_cursor = self.db_cursor

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
        self.db_cursor.execute(
            "SELECT name FROM path_structures WHERE id = ?", (file_id,)
        )
        _result = self.db_cursor.fetchall()

        _len = len(_result)

        if _len == 1:
            return _result[0][0]
        elif _len == 0:
            return False
        else:
            raise RuntimeError("Wrong result length")

    def main(self):
        conn = self.conn  # 设置别名

        es = gettext.translation(
            "connHandler",
            localedir=self.root_abspath + "/content/locale",
            languages=[self.locale],
            fallback=True,
        )
        es.install()

        try:
            if not self._doFirstCommunication(conn):
                conn.close()
                sys.exit()
            else:
                self.__send(json.dumps({"msg": "ok", "code": 0}))  # 发送成功回答
        except:
            self.log.logger.info(f"{self.addr}: Handshake failed.")
            self.log.logger.debug(
                f"{self.addr}: Error details for this handshake process:", exc_info=True
            )
            self.conn.close()
            sys.exit()

        while not self.terminate_event.is_set():
            try:
                recv = self.__recv()
            except ValueError:  # Wrong IV, etc.
                try:
                    self.__send("?")
                except:
                    raise
                continue
            except ConnectionAbortedError:
                self.log.logger.info(f"{self.addr}: Connection aborted")
                sys.exit()
            except ConnectionResetError:
                self.log.logger.info(f"{self.addr}: Connection reset")
                sys.exit()
            except TimeoutError:
                self.log.logger.info(
                    f"{self.addr}: Connection timed out. Disconnecting."
                )
                self.conn.close()
                sys.exit()
            # print(f"recv: {recv}")

            try:
                loaded_recv = json.loads(recv)
            except Exception as e:
                self.log.logger.debug(f"Error when loading recv: {e}")
                self.__send(json.dumps({"code": -1, "msg": "invaild request format"}))
                continue

            client_api_version = loaded_recv.get("version", None)

            # 判断 API 版本
            if not client_api_version:
                self.__send(json.dumps({"code": -1, "msg": "API version is not given"}))
                continue

            if client_api_version == 1:
                self.handle_v1(loaded_recv)
            else:  # 目前仅支持 V1
                self.__send(json.dumps({"code": -1, "msg": "unsupported API version"}))
                continue

        self.log.logger.debug(
            f"terminate_event 被激活，正在终止线程 {self.thread_name}..."
        )

        self.log.logger.debug("正在终止与客户端和数据库的连接...")
        self.conn.close()
        self.db_conn.close()

        sys.exit()

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

        if user.hasRights(("super_access",)):
            return True  # 放行超级权限，避免管理员被锁定在外

        # 确认是否满足 deny 规则
        if check_deny:
            # print(access_rules)
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
        if user.ifMatchRules(access_rules[action]):
            return True

        if external_access:
            for i in external_access["groups"]:
                if action not in (i_dict := external_access["groups"][i]).keys():
                    continue
                if (not (expire_time := i_dict[action].get("expire", 0))) or (
                    expire_time >= time.time()
                ):  # 如果用户组拥有的权限尚未到期
                    if user.hasGroups((i,)):  # 如果用户存在于此用户组
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

    def createFileTask(
        self,
        file_ids: Iterable,
        username,
        task_id=None,
        operation="read",
        expire_time=None,
        force_write=False,
    ):
        fqueue_db = sqlite3.connect(f"{self.root_abspath}/content/fqueue.db")

        fq_cur = fqueue_db.cursor()

        if not task_id:
            task_id = secrets.token_hex(64)

        if expire_time == None:
            expire_time = time.time() + 3600  # by default

        token_hash = secrets.token_hex(64)
        token_salt = secrets.token_hex(16)

        token_hash_sha256 = hashlib.sha256(token_hash.encode()).hexdigest()
        final_token_hash_obj = hashlib.sha256()
        final_token_hash_obj.update((token_hash_sha256 + token_salt).encode())

        final_token_hash = final_token_hash_obj.hexdigest()

        token_to_store = (final_token_hash, token_salt)

        # fake_dir(set to task_id)
        fake_dir = task_id[32:]

        # Iterable: allocate fake_id for per file

        insert_list = []
        return_id_dict = {}  # file_id: fake_id

        for per_file_id in file_ids:
            this_fake_id = secrets.token_hex(16)

            if operation == "write":
                fq_cur.execute(
                    'SELECT * FROM ft_queue WHERE file_id = ? AND operation = "write" AND done = 0 AND expire_time > ?;',
                    (
                        per_file_id,
                        time.time(),
                    ),
                )
                query_result = fq_cur.fetchall()

                if query_result and not force_write:
                    raise PendingWriteFileError(
                        "文件存在至少一需要写入的任务，且该任务尚未完成"
                    )

            insert_list.append(
                (
                    task_id,
                    username,
                    operation,
                    json.dumps(token_to_store),
                    this_fake_id,
                    fake_dir,
                    per_file_id,
                    expire_time,
                )
            )

            return_id_dict[per_file_id] = this_fake_id

        fq_cur.executemany(
            "INSERT INTO ft_queue (task_id, username, operation, token, fake_id, fake_dir, file_id, expire_time, done, cleared) \
                        VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, 0, 0 );",
            insert_list,
        )

        fqueue_db.commit()
        fqueue_db.close()

        return task_id, token_hash_sha256, return_id_dict, expire_time

    def cancelFileTask(self, task_id):
        fqueue_db = sqlite3.connect(f"{self.root_abspath}/content/fqueue.db")
        fq_cur = fqueue_db.cursor()

        fq_cur.execute(
            "SELECT FROM ft_queue WHERE task_id = ? AND done = 0 AND expire_time > ?",
            (task_id, time.time()),
        )
        query_result = fq_cur.fetchall()

        if not query_result:  # 如果任务已经完成，或并未存在
            return False

        fq_cur.execute(
            "UPDATE ft_queue SET done = -2 WHERE task_id = ? AND done = 0 AND expire_time > ?;",
            (task_id, time.time()),
        )
        fqueue_db.commit()
        fqueue_db.close()

        return True

    def permanentlyDeleteFile(
        self, fake_path_id
    ):  # TODO #15 更新操作至适配 revision 的版本
        g_cur = self.db_cursor

        # 查询文件信息

        g_cur.execute(
            "SELECT `type`, `revisions` FROM path_structures WHERE `id` = ?",
            (fake_path_id,),
        )
        query_result = g_cur.fetchall()

        if len(query_result) == 0:
            raise FileNotFoundError
        elif len(query_result) > 1:
            raise ValueError("在查询表 path_structures 时发现不止一条同路径 id 的记录")

        got_type, revisions = query_result[0]

        revisions = json.loads(revisions)

        if got_type != "file":
            raise TypeError("删除的必须是一个文件")

        # 先初始化 fq_db
        fq_db = sqlite3.connect(f"{self.root_abspath}/content/fqueue.db")
        fq_cur = fq_db.cursor()

        # 查询 document_indexes 表

        for revision_id in revisions:
            this_index_file_id = revisions[revision_id]["file_id"]

            g_cur.execute(
                "SELECT `abspath` FROM document_indexes WHERE `id` = ?",
                (this_index_file_id,),
            )

            index_query_result = g_cur.fetchall()

            if len(index_query_result) == 0:
                raise FileNotFoundError(
                    f"在处理 Rev ID: {revision_id} 的删除时，未发现在 path_structures 中所指定的文件 id '{this_index_file_id}' 的记录"
                )
            elif len(index_query_result) > 1:
                raise ValueError(
                    f"在处理 Rev ID: {revision_id} 的删除时，在查询表 document_indexes 时发现不止一条同 id 的记录"
                )

            file_abspath = index_query_result[0][0]

            if not file_abspath:
                raise ValueError("file_abspath 必须有值")

            # 删除表记录

            g_cur.execute(
                "DELETE from `document_indexes` where `id` = ?;", (this_index_file_id,)
            )
            g_cur.execute(
                "DELETE from `path_structures` where `id` = ?;", (fake_path_id,)
            )

            self.db_conn.commit()

            # 移除所有传输任务列表

            fq_db = sqlite3.connect(f"{self.root_abspath}/content/fqueue.db")
            fq_cur = fq_db.cursor()

            fq_cur.execute(
                "DELETE from ft_queue WHERE file_id = ? AND done = 0;",
                (this_index_file_id,),
            )  #  AND done = 0

            # 删除真实文件
            os.remove(file_abspath)

        fq_db.commit()
        fq_db.close()

        return True

    def deleteDir(self, dir_id, user: Users, delete_after=0):
        handle_cursor = self.db_cursor

        completed_list = []
        failed_list = []

        new_state = {"code": "deleted", "expire_time": time.time() + delete_after}

        # 判断是否有权限

        # 遍历下级文件夹
        handle_cursor.execute(
            'SELECT `id` FROM path_structures WHERE `parent_id` = ? AND `type` = "dir";',
            (dir_id,),
        )

        query_subs_result = handle_cursor.fetchall()

        for i in query_subs_result:
            sub_result = self.deleteDir(i[0], user)

            completed_list += sub_result[0]
            failed_list += sub_result[1]

        # 获取本级列表
        handle_cursor.execute(
            "SELECT `id` FROM path_structures WHERE `parent_id` = ?", (dir_id,)
        )
        query_result = handle_cursor.fetchall()

        for i in query_result:
            if not self.verifyUserAccess(i[0], "delete", user):
                failed_list.append(i[0])
            else:
                # 删除该目录的直系子级文件和目录
                handle_cursor.execute(
                    "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
                    (json.dumps(new_state), i[0]),
                )
                completed_list.append(i[0])

        if not failed_list:  # 仅当删除下级文件未出现错误时才删除目录
            handle_cursor.execute(
                "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
                (json.dumps(new_state), dir_id),
            )
            completed_list.append(dir_id)
        else:
            failed_list.append(dir_id)

        self.db_conn.commit()

        return completed_list, failed_list

    def recoverDir(self, dir_id, user: Users):
        # 注意：前后两个函数都不对用户是否有该文件夹权限做判断，应在 handle 部分完成

        handle_cursor = self.db_cursor

        completed_list = []
        failed_list = []

        new_state = {"code": "ok", "expire_time": 0}

        # 判断是否有权限

        # 遍历下级文件夹
        handle_cursor.execute(
            'SELECT `id` FROM path_structures WHERE `parent_id` = ? AND `type` = "dir";',
            (dir_id,),
        )

        query_subs_result = handle_cursor.fetchall()

        for i in query_subs_result:
            sub_result = self.recoverDir(i[0])

            completed_list += sub_result[0]
            failed_list += sub_result[1]

        # 获取本级列表
        handle_cursor.execute(
            "SELECT `id` FROM path_structures WHERE `parent_id` = ?", (dir_id,)
        )
        query_result = handle_cursor.fetchall()

        for i in query_result:
            if not self.verifyUserAccess(i[0], "recover", user):
                failed_list.append(i[0])
            else:
                # 恢复该目录的直系子级文件和目录
                handle_cursor.execute(
                    "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
                    (json.dumps(new_state), i[0]),
                )
                completed_list.append(i[0])

        # 无论是否全部恢复成功都恢复此目录
        handle_cursor.execute(
            "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
            (json.dumps(new_state), dir_id),
        )
        completed_list.append(dir_id)

        self.db_conn.commit()

        return completed_list, failed_list

    def getFileSize(self, path_id, rev_id=None):
        g_cur = self.db_cursor

        g_cur.execute(
            "SELECT `type`, `revisions` FROM path_structures WHERE `id` = ?", (path_id,)
        )

        query_result = g_cur.fetchall()

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

        g_cur.execute(
            "SELECT `abspath` FROM document_indexes WHERE `id` = ?", (this_rev_file_id,)
        )

        query_result = g_cur.fetchall()

        if len(query_result) == 0:
            raise FileNotFoundError("在 document_indexes 表中未发现对应的数据")
        elif len(query_result) > 1:
            raise RuntimeError(
                "在执行 getFileSize 操作时发现数据库出现相同ID的多条记录"
            )

        this_real_file_result = query_result[0]

        # cleanup
        # g_cur.close()

        if SYS_LOCKS["SYS_IOLOCK"].acquire(timeout=0.75):
            filesize = os.path.getsize(this_real_file_result[0])
            SYS_LOCKS["SYS_IOLOCK"].release()
            return filesize
        else:  # 如果超时
            return -1

    def filterPathProperties(self, properties: dict):
        result = properties

        # TODO #11

        return result

    def filterUserProperties(self, properties: dict):
        return properties  # TODO #11

    def userOperationAuthWrapper(func):
        @wraps(func)
        def _wrapper(self: Self, *args, **kwargs):
            ### 通用用户令牌鉴权开始

            # 验证 token

            user = Users(self.this_time_username, self.db_conn, self.db_cursor)

            # 读取 token_secret
            with open(f"{self.root_abspath}/content/auth/token_secret", "r") as ts_file:
                token_secret = ts_file.read()

            if not user.isVaildToken(self.this_time_token, token_secret):
                self.__send(
                    json.dumps({"code": -1, "msg": "invaild token or username"})
                )
                return

            user.load()

            ### 结束

            func(self, *args, **kwargs, user=user)  # 仅当上述操作成功该函数才会被执行

        return _wrapper

    def verifyUserAccess(self, id, action, user: Users, checkdeny=True, _subcall=False):
        """
        用户鉴权函数。
        用于逐级检查用户是否拥有访问权限，若发生任意无情况即返回 False
        """

        # print(self.db_cursor._connection)
        por_policy = Policies("permission_on_rootdir", self.db_conn, self.db_cursor)

        if id == None:
            raise ValueError
        elif not id:
            self.log.logger.debug("请求验证的路径是根目录")

            por_access_rules = por_policy["rules"]["access_rules"]
            por_external_access = por_policy["rules"]["external_access"]

            if not self._verifyAccess(
                user, action, por_access_rules, por_external_access, checkdeny
            ):
                self.log.logger.debug("PoR 鉴权失败")
                return False
            else:
                self.log.logger.debug("PoR 鉴权成功")
                return True

        self.log.logger.debug(
            f"verifyUserAccess(): 正在对 用户 {user.username} 访问 id: {id} 的请求 进行鉴权"
        )

        db_cur = self.db_cursor

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
            self.log.logger.debug("_subcall 为真")

            if result[0][3] != "dir":
                raise TypeError("Not a directory: does not support _subcall")

            if not access_rules.get(
                "__subinherit__", True
            ):  # 如果设置为下层不继承（对于文件应该无此设置）
                self.log.logger.debug("本层设置为下层不继承，返回为真")
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
                self.log.logger.debug("将检查上级目录的 deny 规则")
                parent_checkdeny = True
            else:
                parent_checkdeny = False

            if parent := result[0][0]:  # 如果仍有父级
                self.log.logger.debug(f"正在检查其父目录 {parent} 的权限...")
                if not self.verifyUserAccess(
                    parent, action, user, checkdeny=parent_checkdeny, _subcall=True
                ):
                    return False
                self.log.logger.debug("完毕，无事发生。")

            elif por_policy["inherit_by_subdirectory"]:  # 如果没有父级（是根目录）
                if not self.verifyUserAccess("", action, user, parent_checkdeny, True):
                    return False

        else:
            self.log.logger.debug("请求操作在该路径上被设置为不继承上层设置，跳过")

        self.log.logger.debug(
            f"所有访问规则和附加权限记录：{access_rules}, {external_access}"
        )

        if self._verifyAccess(
            user, action, access_rules, external_access, check_deny=checkdeny
        ):
            self.log.logger.debug(
                f"verifyUserAccess(): 用户 {user.username} 对于 id: {id} 的请求 鉴权成功"
            )
            return True

        self.log.logger.debug("校验失败。")
        return False

    def handle_v1(self, loaded_recv):
        self.log.logger.debug("handle_v1() 函数被调用")

        if loaded_recv["request"] == "login":
            try:
                req_username = loaded_recv["data"].get("username", "")
                req_password = loaded_recv["data"].get("password", "")
                if (not req_username) or (not req_password):
                    raise ValueError
            except KeyError:
                self.log.logger.debug("提交的请求没有提供 data 键值")
                self.__send(json.dumps({"code": -1, "msg": "invaild arguments"}))
                return
            except ValueError:
                self.log.logger.debug(
                    "提交的请求没有提供用户名或密码（可能 data 下对应键值为空）"
                )
                self.__send(
                    json.dumps({"code": -2, "msg": "no username or password provided"})
                )
                return

            self.log.logger.debug(
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

            self.log.logger.info(f"{self.addr}: 客户端断开连接")

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
            self.log.logger.debug("请求无效：认证数据不完整或缺失")
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
                self.log.logger.info(f"{req_username} 密码正确，准予访问")
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
                self.log.logger.info(f"{req_username} 密码错误，拒绝访问")

                user_auth_policy = Policies("user_auth", self.db_conn, self.db_cursor)
                sleep_for_fail = user_auth_policy["sleep_when_login_fail"]

                if sleep_for_fail:
                    self.log.logger.debug(f"正根据登录策略睡眠 {sleep_for_fail} 秒")
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
                self.log.logger.debug(f"正根据登录策略睡眠 {sleep_for_fail} 秒")
                time.sleep(sleep_for_fail)

            self.__send(json.dumps({"code": 401, "msg": fail_msg}))

    def handle_logout(self):
        pass

    def handle_refreshToken(self, loaded_recv):
        old_token = loaded_recv["auth"]["token"]
        req_username = loaded_recv["auth"]["username"]

        user = Users(req_username, self.db_conn, self.db_cursor)  # 初始化用户对象
        # 读取 token_secret
        with open(f"{self.root_abspath}/content/auth/token_secret", "r") as ts_file:
            token_secret = ts_file.read()

        if new_token := user.refreshUserToken(
            old_token, token_secret, vaild_time=3600
        ):  # return: {token} , False
            self.__send(json.dumps({"code": 0, "msg": "ok", "token": new_token}))
        else:
            self.__send(json.dumps({"code": 401, "msg": "invaild token or username"}))

    @userOperationAuthWrapper
    def handle_getRootDir(self, loaded_recv, user: Users):
        por_policy = Policies("permission_on_rootdir", self.db_conn, self.db_cursor)

        por_access_rules = por_policy["rules"]["access_rules"]
        por_external_access = por_policy["rules"]["external_access"]

        # 增加对 view_deleted 的判断
        view_deleted = loaded_recv["data"].get("view_deleted", False)

        if view_deleted:  # 如果启用 view_deleted 选项
            if not user.hasRights(("view_deleted",)):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        if not self._verifyAccess(
            user, "read", por_access_rules, por_external_access, True
        ):
            self.log.logger.debug("用户无权访问根目录")
            self.__send(json.dumps({"code": 403, "msg": "forbidden"}))
            return
        else:
            self.log.logger.debug("根目录鉴权成功")

        handle_cursor = self.db_cursor

        handle_cursor.execute(
            "SELECT `id`, `name`, `type`, `properties`, `state` FROM path_structures WHERE `parent_id` = ?",
            ("",),
        )
        all_result = handle_cursor.fetchall()

        dir_result = dict()

        for i in all_result:
            this_object_state = json.loads(i[4])

            if this_object_state["code"] == "deleted":
                if not view_deleted:
                    continue

            if not self.verifyUserAccess(
                i[0], "read", user
            ):  # 检查该目录下的文件是否有权访问，如无则隐藏
                if self.config["security"]["hide_when_no_access"]:
                    continue
                else:
                    pass

            original_properties = json.loads(i[3])

            filtered_properties = self.filterPathProperties(original_properties)

            if i[2] == "file":
                filtered_properties["size"] = self.getFileSize(i[0])

            # print(i)
            dir_result[i[0]] = {
                "name": i[1],
                "type": i[2],
                "state": this_object_state,
                "properties": filtered_properties,
            }

        self.__send(json.dumps({"code": 0, "dir_data": dir_result}))

        return

    @userOperationAuthWrapper
    def handle_getPolicy(self, loaded_recv, user: Users):
        req_policy_id = loaded_recv["data"]["policy_id"]

        action = "read"  # "getPolicy"，所以目前 action 就是 read

        handle_cursor = self.db_cursor
        handle_cursor.execute(
            "SELECT `content`, `access_rules`, `external_access` FROM `policies` WHERE `id` = ?",
            (req_policy_id,),
        )

        fetched = handle_cursor.fetchone()
        # 不是很想再写判断是否有重复ID的逻辑，反正出了问题看着办吧，这不是我要考虑的事

        if not fetched:  # does not exist
            self.__send(
                json.dumps(
                    {"code": 404, "msg": "the policy you've requested does not exist"}
                )
            )
            return

        content = json.loads(fetched[0])
        access_rules = json.loads(fetched[1])
        external_access = json.loads(fetched[2])

        if not self._verifyAccess(user, action, access_rules, external_access):
            self.__send(json.dumps({"code": 403, "msg": "forbidden"}))
        else:
            self.__send(json.dumps({"code": 0, "data": content}))

        return

    @userOperationAuthWrapper
    def handle_getAvatar(self, loaded_recv, user: Users):
        if not (avatar_username := loaded_recv["data"].get("username")):
            self.__send(json.dumps({"code": -1, "msg": "needs a username"}))
            return

        get_avatar_user = Users(avatar_username, self.db_conn, self.db_cursor)

        if not get_avatar_user.ifExists():
            self.log.logger.debug(
                f"用户 {user.username} 试图请求帐户 {avatar_username} 的头像，但这个用户并不存在。"
            )
            self.__send(json.dumps({"code": 404, "msg": "not found"}))
            return

        avatar_policy = Policies("avatars", self.db_conn, self.db_cursor)

        ### TODO #9 增加用户权限对头像获取权限的支持 - done

        gau_access_rules = get_avatar_user["publicity"].get("access_rules", {})
        gau_external_access = get_avatar_user["publicity"].get("external_access", {})

        if get_avatar_user["publicity"].get("restricted", False):
            if (
                (not avatar_policy["allow_access_without_permission"])
                and (
                    not self._verifyAccess(
                        user, "read", gau_access_rules, gau_external_access
                    )
                )
                and (not user.hasRights(("super_useravatar",)))
            ):
                self.__send(json.dumps({"code": 403, "msg": "forbidden"}))
                return

        if avatar_file_id := get_avatar_user["avatar"].get("file_id", None):
            task_id, task_token, t_filenames = self.createFileTask(
                (avatar_file_id,), user.username
            )

            mapping = {"": avatar_file_id}

            mapped_dict = convertFile2PathID(t_filenames, mapping)

            self.__send(
                json.dumps(
                    {
                        "code": 0,
                        "msg": "ok",
                        "data": {
                            "task_id": task_id,
                            "task_token": task_token,
                            "t_filename": mapped_dict,
                        },
                    }
                )
            )
        else:
            if default_avatar_id := avatar_policy["default_avatar"]:
                task_id, task_token, t_filenames, expire_time = self.createFileTask(
                    (default_avatar_id,), user.username
                )

                mapping = {"": default_avatar_id}

                mapped_dict = convertFile2PathID(t_filenames, mapping)

                self.log.logger.debug(
                    f"用户 {user.username} 请求帐户 {avatar_username} 的头像，返回为默认头像。"
                )

                self.__send(
                    json.dumps(
                        {
                            "code": 0,
                            "msg": "ok",
                            "data": {
                                "task_id": task_id,
                                "task_token": task_token,
                                "t_filename": mapped_dict,
                                "expire_time": expire_time,
                            },
                        }
                    )
                )
            else:
                self.log.logger.debug(
                    f"用户 {user.username} 试图请求帐户 {avatar_username} 的头像，但用户未设置头像，且策略指定的默认头像为空。"
                )
                self.__send(json.dumps({"code": 404, "msg": "not found", "data": {}}))

    @userOperationAuthWrapper
    def handle_createFile(self, loaded_recv, user: Users):
        if "data" not in loaded_recv:
            self.__send(json.dumps({self.RES_MISSING_ARGUMENT}))

        target_directory_id = loaded_recv["data"].get(
            "directory_id", ""
        )  # fallback to rootdir
        target_file_path_id = loaded_recv["data"].get("file_id", None)
        target_filename = loaded_recv["data"].get(
            "filename", f"Untitled-{int(time.time())}"
        )

        if target_file_path_id:
            if len(target_file_path_id) > 64:
                self.__send(json.dumps({"code": -1, "msg": "file id too long"}))
                return
        else:
            target_file_path_id = secrets.token_hex(8)

        handle_cursor = self.db_cursor

        handle_cursor.execute(
            "SELECT 1 FROM path_structures WHERE id = ?", (target_file_path_id,)
        )

        query_result = handle_cursor.fetchall()

        if query_result:
            self.__send(
                json.dumps(
                    {
                        "code": -1,
                        "msg": "file or directory exists.",
                        "__hint__": "if you want to override a file, use 'operateFile' instead.",
                    }
                )
            )
            return

        del query_result  # 清除

        if target_directory_id:  # 如果不是根目录
            handle_cursor.execute(
                "SELECT `type` FROM path_structures WHERE `id` = ?",
                (target_directory_id,),
            )

            dir_query_result = handle_cursor.fetchall()

            if not dir_query_result:
                self.__send(
                    json.dumps({"code": 404, "msg": "target directory not found"})
                )
                return
            elif len(dir_query_result) > 1:
                raise RuntimeError("数据库出现了不止一条同id的记录")

            if (d_id_type := dir_query_result[0][0]) != "dir":
                self.log.logger.debug(
                    f"用户试图请求在 id 为 {target_directory_id} 的目录下创建文件，\
                                    但它事实上不是一个目录（{d_id_type}）"
                )
                self.__send(json.dumps({"code": -1, "msg": "not a directory"}))
                return

            if not self.verifyUserAccess(target_directory_id, "write", user):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        else:
            por_policy = Policies("permission_on_rootdir", self.db_conn, self.db_cursor)

            por_access_rules = por_policy["rules"]["access_rules"]
            por_external_access = por_policy["rules"]["external_access"]

            if not self._verifyAccess(
                user, "write", por_access_rules, por_external_access, True
            ):
                self.log.logger.debug("用户无权访问根目录")
                self.__send(self.RES_ACCESS_DENIED)
                return
            else:
                self.log.logger.debug("根目录鉴权成功")

        # 开始创建文件

        index_file_id = secrets.token_hex(64)  # 存储在 document_indexes 中
        real_filename = secrets.token_hex(16)

        today = datetime.date.today()

        destination_path = (
            f"{self.root_abspath}/content/files/{today.year}/{today.month}"
        )

        os.makedirs(destination_path, exist_ok=True)  # 即使文件夹已存在也加以继续

        with open(f"{destination_path}/{real_filename}", "w") as new_file:
            pass

        # 注册数据库条目

        ### 创建一个新的 revision

        # 构造
        new_revision_id: str = uuid.uuid4().hex
        new_revision_data = {
            "file_id": index_file_id,
            "state": {"code": "ok", "expire_time": 0},
            "access_rules": {},
            "external_access": {},
            "time": time.time(),
        }

        initial_revisions = {new_revision_id: new_revision_data}

        # handle_cursor.execute("BEGIN TRANSACTION;")

        handle_cursor.execute(
            "INSERT INTO document_indexes (`id`, `abspath`) VALUES (?, ?)",
            (index_file_id, destination_path + "/" + real_filename),
        )

        handle_cursor.execute(
            "INSERT INTO path_structures \
                              (`id` , `name` , `owner` , `parent_id` , `type` , `revisions` , `access_rules`, `external_access`, `properties`, `state`) \
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                target_file_path_id,
                target_filename,
                json.dumps((("user", user.username),)),
                target_directory_id,
                "file",
                json.dumps(initial_revisions),
                r"{}",
                r"{}",
                json.dumps({"created_time": time.time()}),
                json.dumps({"code": "ok", "expire_time": 0}),
            ),
        )

        # handle_cursor.execute("COMMIT TRANSACTION;")
        self.db_conn.commit()

        # 创建任务
        task_id, task_token, t_filenames, expire_time = self.createFileTask(
            (index_file_id,), operation="write", username=user.username
        )

        mapped_dict = convertFile2PathID(
            t_filenames, {target_file_path_id: index_file_id}
        )

        self.__send(
            json.dumps(
                {
                    "code": 0,
                    "msg": "file created",
                    "data": {
                        "task_id": task_id,
                        "task_token": task_token,
                        "t_filename": mapped_dict,
                        "expire_time": expire_time,
                    },
                }
            )
        )

        return

    @userOperationAuthWrapper
    def handle_operateFile(self, loaded_recv, user: Users):
        if "data" not in loaded_recv:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        if not loaded_recv["data"].get("action", None):
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        file_id: str = loaded_recv["data"].get("file_id", None)  # 伪路径文件 ID
        view_deleted = loaded_recv["data"].get("view_deleted", False)

        # 处理 revision_id
        specified_revision_id = loaded_recv["data"].get("revision_id", None)

        if not file_id:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        if loaded_recv["data"]["action"] == "recover":
            view_deleted = True  # 若要恢复文件，则必须有权访问被删除的文件

        if view_deleted:  # 如果启用 view_deleted 选项
            if not user.hasRights(("view_deleted",)):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        handle_cursor = self.db_cursor

        handle_cursor.execute(
            "SELECT `name`, `parent_id`, `type`, `revisions`, `access_rules`, `external_access`, `properties`, `state` \
                              FROM path_structures WHERE `id` = ?",
            (file_id,),
        )

        result = handle_cursor.fetchall()

        if len(result) > 1:
            raise ValueError("Invaild query result length")
        elif len(result) < 1:
            self.__send(json.dumps({"code": -1, "msg": "no such file"}))
            return

        # 判断文档总体是否被删除
        if (file_state := json.loads(result[0][7]))["code"] == "deleted":
            # 如下，file_state 不一定是 file 的 state，但由于安全性原因只能先写这个判断
            if not view_deleted:
                self.__send(json.dumps(self.RES_NOT_FOUND))
                return

        # 判断文档是否是个文档（雾）
        if result[0][2] != "file":
            self.__send(json.dumps({"code": -1, "msg": "not a file"}))
            return

        # 获取请求的操作
        req_action = loaded_recv["data"]["action"]

        # 首先判断该操作是否由文档所允许（但可能放在后面也行）
        if not self.verifyUserAccess(file_id, req_action, user, _subcall=False):
            self.__send(json.dumps(self.RES_ACCESS_DENIED))
            self.log.logger.debug("权限校验失败：无权在文档下执行所请求的操作")
            return

        # 查询文档下的所有历史版本
        query_revisions: dict = json.loads(result[0][3])

        if not specified_revision_id:  # 如果未指定 rev
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

            if not newest_revision and req_action in [
                "read",
                "delete_rev",
                "recover_rev",
            ]:  # 如果没有满足条件的 newest_revision
                self.__send(json.dumps(self.RES_NOT_FOUND))
                return

            specified_revision_id, specified_revision_data = (
                newest_revision if newest_revision else (None, None)
            )  # 指定

        else:  # 如果已经指定
            # 判断是否有该 rev
            if specified_revision_id not in query_revisions:
                self.__send(
                    json.dumps({"code": 404, "msg": "specified revision not found"})
                )
                return

            # 判断 rev 版本是否被删除（在特别指定了 rev_id 的时候才会出现）

            if query_revisions[specified_revision_id]["state"] == "deleted":
                if not view_deleted:
                    self.__send(
                        json.dumps({"code": 404, "msg": "specified revision not found"})
                    )
                    return

            specified_revision_data: dict = query_revisions[specified_revision_id]

        # 正式处理对文件的操作，实际指向确定的 rev
        # 获取 revision <- getFileRevisions()

        self.log.logger.debug(
            f"请求对文件版本ID {specified_revision_id} 的操作：{req_action}"
        )

        if req_action in [
            "read",
            "write",
            "rename",
            "delete",
            "permanently_delete",
            "recover",
            "move",
            "change_id",
            "delete_rev",
            "recover_rev",
        ]:
            # 注意：write 操作仅支持覆盖，创建请使用 uploadFile

            # 在检查文档整体的权限的同时检查对特定版本的权限
            if not self._verifyAccess(
                user,
                req_action,
                specified_revision_data["access_rules"],
                specified_revision_data["external_access"],
            ):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                self.log.logger.debug("权限校验失败：无权在该历史版本执行所请求的操作")
                return

            specified_revision_file_id: str = specified_revision_data["file_id"]

            if req_action == "read":
                # 权限检查已在上一步完成

                (
                    task_id,
                    task_token,
                    fake_file_ids,
                    expire_time,
                ) = self.createFileTask(
                    (specified_revision_file_id,),
                    operation="read",
                    expire_time=time.time() + 3600,
                    username=user.username,
                )

                mapping = {
                    file_id: specified_revision_file_id
                }  # 伪路径文件ID: 该版本 index 表 文件ID

                response = {
                    "code": 0,
                    "msg": "ok",
                    "data": {
                        "task_id": task_id,
                        "task_token": task_token,  # original hash after sha256
                        "expire_time": expire_time,
                        "t_filename": convertFile2PathID(fake_file_ids, mapping),
                    },
                }

                self.__send(json.dumps(response))

            elif (
                req_action == "write"
            ):  # 该操作将使得最新版本的 revision 指向给定的文件
                do_force_write = loaded_recv["data"].get("force_write", False)

                if file_state_code := file_state["code"] != "ok":
                    if file_state_code == "locked":
                        self.__send(
                            json.dumps(
                                {
                                    "code": -1,
                                    "msg": "file locked",
                                    "data": {
                                        "expire_time": file_state.get("expire_time", 0)
                                    },
                                }
                            )
                        )

                    elif file_state_code == "deleted":
                        self.__send(
                            json.dumps(
                                {
                                    "code": -1,
                                    "msg": "The file has been marked for deletion, please restore it first",
                                    "data": {
                                        "expire_time": file_state.get("expire_time", 0)
                                    },
                                }
                            )
                        )

                    else:
                        self.__send(
                            json.dumps({"code": -1, "msg": "unexpected file status"})
                        )

                    return

                ### 创建一个新的 revision

                # 得到新的随机文件ID，此时文件应当已创建
                new_revision_file_id: str = self._createFileIndex()

                # 构造
                new_revision_id: str = uuid.uuid4().hex
                new_revision_data = {
                    "file_id": new_revision_file_id,
                    "state": {"code": "ok", "expire_time": 0},
                    "access_rules": {},
                    "external_access": {},
                    "time": time.time(),
                }

                ## 写入新的 revision

                # 开启事务
                # handle_cursor.execute("BEGIN TRANSACTION;")

                # 读取
                handle_cursor.execute(
                    "SELECT `revisions` FROM path_structures WHERE `id` = ?", (file_id,)
                )
                _revisions_now = json.loads(
                    handle_cursor.fetchone()[0]
                )  # 由于主键的互异性，此处应该仅有一条结果

                _insert_revisions = _revisions_now
                _insert_revisions[new_revision_id] = new_revision_data

                handle_cursor.execute(
                    "UPDATE path_structures SET `revisions` = ? WHERE `id` = ?; ",
                    (json.dumps(_insert_revisions), file_id),
                )

                self.db_conn.commit()

                ## 创建传输任务

                try:
                    (
                        task_id,
                        task_token,
                        fake_file_ids,
                        expire_time,
                    ) = self.createFileTask(
                        (new_revision_file_id,),
                        operation="write",
                        expire_time=time.time() + 3600,
                        force_write=do_force_write,
                        username=user.username,
                    )
                except PendingWriteFileError:
                    self.__send(json.dumps({"code": -1, "msg": "file already in use"}))
                    return

                mapping = {file_id: new_revision_file_id}

                response = {
                    "code": 0,
                    "msg": "ok",
                    "data": {
                        "task_id": task_id,
                        "task_token": task_token,  # original hash after sha256
                        "expire_time": expire_time,
                        "t_filename": convertFile2PathID(
                            fake_file_ids, mapping
                        ),  # 这个ID是客户端上传文件时应当使用的文件名
                    },
                }

                self.__send(json.dumps(response))

            elif req_action == "rename":
                new_filename = loaded_recv["data"].get("new_filename", None)

                if not new_filename:  # filename 不能为空
                    self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
                    return

                if file_state_code := file_state["code"] != "ok":
                    if file_state_code == "locked":
                        self.__send(
                            json.dumps(
                                {
                                    "code": -1,
                                    "msg": "file locked",
                                    "data": {
                                        "expire_time": file_state.get("expire_time", 0)
                                    },
                                }
                            )
                        )
                        return

                handle_cursor.execute(
                    "UPDATE path_structures SET `name` = ? WHERE `id` = ?;",
                    (new_filename, file_id),
                )

                self.db_conn.commit()

                self.__send(json.dumps({"code": 0, "msg": "success"}))

            elif req_action == "delete":
                recycle_policy = Policies("recycle", self.db_conn, self.db_cursor)
                delete_after_marked_time = recycle_policy["deleteAfterMarked"]

                if file_state["code"] == "deleted":
                    self.__send(
                        json.dumps(
                            {
                                "code": -1,
                                "msg": "The file has been marked for deletion",
                            }
                        )
                    )
                    return

                new_state = {
                    "code": "deleted",
                    "expire_time": time.time() + delete_after_marked_time,
                }

                handle_cursor.execute(
                    "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
                    (json.dumps(new_state), file_id),
                )

                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))

            elif req_action == "recover":
                if file_state["code"] != "deleted":
                    self.__send(json.dumps({"code": -1, "msg": "File is not deleted"}))
                    return

                recovered_state = {"code": "ok", "expire_time": 0}

                handle_cursor.execute(
                    "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
                    (json.dumps(recovered_state), file_id),
                )

                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))

            elif req_action == "permanently_delete":
                self.permanentlyDeleteFile(file_id)

                self.__send(json.dumps(self.RES_OK))

            elif req_action == "move":
                new_parent_id = loaded_recv["data"].get("new_parent", None)

                if new_parent_id == None:
                    self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
                    return

                # 判断新目录是否存在

                handle_cursor = self.db_cursor

                handle_cursor.execute(
                    "SELECT `type` FROM path_structures WHERE `id` = ?",
                    (new_parent_id,),
                )

                query_result = handle_cursor.fetchall()

                if len(query_result) == 0:
                    self.__send(json.dumps(self.RES_NOT_FOUND))
                    return
                elif len(query_result) != 1:
                    raise ValueError("意料之外的记录数量")

                if query_result[0][0] != "dir":
                    self.__send(json.dumps({"code": -1, "msg": "新的路径不是一个目录"}))
                    return

                # 调取原目录

                handle_cursor.execute(
                    "SELECT `parent_id` FROM path_structures WHERE `id` = ?",
                    (file_id,),
                )

                old_parent_result = handle_cursor.fetchone()

                old_parent_id = old_parent_result[0]

                if not self.verifyUserAccess(
                    new_parent_id, "write", user
                ) or not self.verifyUserAccess(old_parent_id, "delete", user):
                    # 移动操作实际上是向新目录写入文件，并删除旧目录文件

                    self.__send(json.dumps(self.RES_ACCESS_DENIED))
                    return

                # 执行操作

                handle_cursor.execute(
                    "UPDATE path_structures SET `parent_id` = ? WHERE `id` = ?;",
                    (new_parent_id, file_id),
                )

                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))

                return

            elif req_action == "change_id":
                if not user.hasRights(("change_id",)):
                    self.__send(json.dumps(self.RES_ACCESS_DENIED))
                    return

                new_id = loaded_recv["data"].get("new_id", None)

                if not new_id:  # id 不能为空
                    self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
                    return

                # 判断新 ID 是否被使用

                handle_cursor = self.db_cursor

                handle_cursor.execute(
                    "SELECT `type` FROM path_structures WHERE `id` = ?", (new_id,)
                )

                result = handle_cursor.fetchall()

                if result:
                    self.__send(json.dumps({"code": -1, "msg": "id exists"}))
                    return

                # 执行操作

                handle_cursor.execute(
                    "UPDATE path_structures SET `id` = ? WHERE `id` = ?;",
                    (new_id, file_id),
                )

                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))

                return

            elif req_action == "delete_rev":  # 删除指定的修订
                recycle_policy = Policies("recycle", self.db_conn, self.db_cursor)
                rev_delete_after_marked_time = recycle_policy["revDeleteAfterMarked"]

                if specified_revision_data["state"]["code"] == "deleted":
                    self.__send(json.dumps({"code": -1, "msg": "already deleted"}))
                    return

                # 执行事务

                # handle_cursor.execute("BEGIN TRANSACTION;")

                # 读取
                handle_cursor.execute(
                    "SELECT `revisions` FROM path_structures WHERE `id` = ?", (file_id,)
                )
                _revisions_now = json.loads(
                    handle_cursor.fetchone()[0]
                )  # 由于主键的互异性，此处应该仅有一条结果

                # 构造写入

                _revisions_now[specified_revision_id]["state"] = {
                    "code": "deleted",
                    "expire_time": time.time() + rev_delete_after_marked_time,
                }

                handle_cursor.execute(
                    "UPDATE path_structures SET `revisions` = ? WHERE `id` = ?;",
                    (_revisions_now, file_id),
                )

                # handle_cursor.execute("COMMIT TRANSACTION;")
                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))

                return

            elif req_action == "recover_rev":
                if specified_revision_data["state"]["code"] != "deleted":
                    self.__send(
                        json.dumps(
                            {"code": -1, "msg": "Specified revision is not deleted"}
                        )
                    )
                    return

                recovered_state = {"code": "ok", "expire_time": 0}

                # 执行事务

                # handle_cursor.execute("BEGIN TRANSACTION;")

                # 读取
                handle_cursor.execute(
                    "SELECT `revisions` FROM path_structures WHERE `id` = ?", (file_id,)
                )
                _revisions_now = json.loads(
                    handle_cursor.fetchone()[0]
                )  # 由于主键的互异性，此处应该仅有一条结果

                # 构造写入

                _revisions_now[specified_revision_id]["state"] = recovered_state

                handle_cursor.execute(
                    "UPDATE path_structures SET `revisions` = ? WHERE `id` = ?;",
                    (_revisions_now, file_id),
                )

                # handle_cursor.execute("COMMIT TRANSACTION;")
                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))

        else:
            self.__send(json.dumps({"code": -1, "msg": "operation not found"}))
            self.log.logger.debug("请求的操作不存在。")
            return

        self.db_conn.commit()

    @userOperationAuthWrapper
    def handle_createUser(self, loaded_recv, user: Users):
        if "data" not in loaded_recv:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        new_usr_username = loaded_recv["data"].get("username", None)
        new_usr_pwd = loaded_recv["data"].get("password", None)

        new_usr_nickname = loaded_recv["data"].get("nickname", new_usr_username)

        if not new_usr_username or not new_usr_pwd:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        # 检查长度是否合法
        if len(new_usr_username) > 32:  # max 255
            self.__send(json.dumps({"code": -1, "msg": "username too long"}))
            return
        if len(new_usr_nickname) > 64:
            self.__send(json.dumps({"code": -1, "msg": "user nickname too long"}))
            return

        if not user.hasRights(("create_user",)):
            self.__send(json.dumps(self.RES_ACCESS_DENIED))
            return

        # 判断用户是否存在
        new_user = Users(new_usr_username, self.db_conn, self.db_cursor)
        if new_user.ifExists():
            self.__send(json.dumps({"code": -1, "msg": "user exists"}))
            return

        new_usr_rights = loaded_recv["data"].get("rights", None)
        new_usr_groups = loaded_recv["data"].get("groups", None)

        auth_policy = Policies("user_auth", self.db_conn, self.db_cursor)

        if new_usr_groups != None or new_usr_rights != None:
            if not user.hasRights(("custom_new_user_settings",)):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        if new_usr_groups == None:  # fallback
            new_usr_groups = auth_policy["default_new_user_groups"]
        if new_usr_rights == None:
            new_usr_rights = auth_policy["default_new_user_rights"]

        handle_cursor = self.db_cursor

        # 随机生成8位salt
        alphabet = string.ascii_letters + string.digits
        salt = "".join(secrets.choice(alphabet) for i in range(8))  # 安全化

        __first = hashlib.sha256(new_usr_pwd.encode()).hexdigest()
        __second_obj = hashlib.sha256()
        __second_obj.update((__first + salt).encode())

        salted_pwd = __second_obj.hexdigest()

        insert_user = (
            new_usr_username,
            salted_pwd,
            salt,
            new_usr_nickname,
            json.dumps(new_usr_rights),
            json.dumps(new_usr_groups),
            json.dumps(auth_policy["default_new_user_properties"]),
            None,  # publickey
        )

        handle_cursor.execute(
            "INSERT INTO `users` VALUES(?, ?, ?, ?, ?, ?, ?, ?)", insert_user
        )

        self.db_conn.commit()

        self.__send(json.dumps(self.RES_OK))

        return

    @userOperationAuthWrapper
    def handle_createGroup(self, loaded_recv, user: Users):
        if "data" not in loaded_recv:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        new_group_name = loaded_recv["data"].get("group_name", None)
        new_group_members = loaded_recv["data"].get("group_members", None)
        new_group_enabled = loaded_recv["data"].get("enabled", None)

        if new_group_name:
            if len(new_group_name) > 32:
                self.__send(json.dumps({"code": -1, "msg": "group name too long"}))
                return
        else:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        if not user.hasRights(("create_group",)):
            self.__send(json.dumps(self.RES_ACCESS_DENIED))
            return

        handle_cursor = self.db_cursor

        # 判断组是否存在
        handle_cursor.execute(
            "SELECT count(`name`) from `groups` where `name` = ?", (new_group_name,)
        )
        result = handle_cursor.fetchone()

        if result[0] != 0:  # 不做过多判断（虽然本该如此）
            self.__send(json.dumps({"code": -1, "msg": "group exists"}))
            return

        new_group_rights = loaded_recv["data"].get("rights", None)

        group_policy = Policies("group_settings", self.db_conn, self.db_cursor)

        if (
            new_group_rights != None or new_group_enabled != None
        ):  # 不为未提供的，因提供空列表也是一种提交
            if not user.hasRights(("custom_new_group_settings",)):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        if new_group_members != None:
            if not user.hasRights(("custom_new_group_members",)):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        if new_group_rights == None:  # fallback
            new_group_rights = group_policy["default_rights"]

        if new_group_members == None:
            new_group_members = group_policy["default_members"]

        if new_group_enabled == None:
            new_group_enabled = group_policy["default_enabled"]
        elif new_group_enabled != 0 and new_group_enabled != 1:
            self.__send(json.dumps({"code": 400, "msg": "group_enabled is invaild"}))
            return

        # 开始处理

        errors = []

        handle_cursor.execute(
            "INSERT INTO `groups` (`name`, `enabled`, `rights`, `properties`) VALUES(?, ?, ?, ?)",  # 插入新的组
            (
                new_group_name,
                new_group_enabled,
                json.dumps(new_group_rights),
                json.dumps({}),
            ),
        )

        for i in new_group_members:
            handle_cursor.execute(
                "SELECT `groups` FROM `users` WHERE `username` = ?", (i,)
            )
            query_result = handle_cursor.fetchone()
            if not query_result:
                errors.append((i, "NOT_FOUND"))
                continue
            old_groups = json.loads(query_result[0])

            new_groups = old_groups  # copy
            new_groups[new_group_name] = {"expire": 0}

            handle_cursor.execute(
                "UPDATE `users` SET `groups` = ? WHERE `username` = ? ",
                (json.dumps(new_groups), i),
            )

        self.db_conn.commit()

        self.__send(json.dumps(self.RES_OK))

        return

    @userOperationAuthWrapper
    def handle_shutdown(self, loaded_recv, user: Users):
        if not user.hasRights(("shutdown",)):
            self.__send(json.dumps(self.RES_ACCESS_DENIED))
            return

        self.terminate_event.set()

        self.__send(json.dumps({"code": 200, "msg": "goodbye"}))

        # 先终止一次连接（可以重复终止）
        self.conn.close()

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host, port = "localhost", self.config["connect"]["port"]
        client_socket.connect((host, port))
        client_socket.close()

        return

    @userOperationAuthWrapper
    def handle_getUserProperties(self, loaded_recv, user: Users):
        if "data" not in loaded_recv:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        target_username = loaded_recv["data"].get("username", user.username)

        if not target_username:
            target_username = user.username  # fallback to whoami

        if target_username != user.username:
            if not user.hasRights(("view_others_properties",)):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

            query_user_object = Users(target_username, self.db_conn, self.db_cursor)
            if not query_user_object.ifExists():
                self.__send(json.dumps(self.RES_NOT_FOUND))
                return

        else:
            query_user_object = user

        response = {
            "rights": list(query_user_object.rights),
            "groups": list(query_user_object.groups),
            "properties": query_user_object.properties,
        }

        self.__send(json.dumps(response))
        return

    @userOperationAuthWrapper
    def handle_operateDir(self, loaded_recv, user: Users):
        if "data" not in loaded_recv:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        if not (action := loaded_recv["data"].get("action", None)):
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        if not (dir_id := loaded_recv["data"].get("dir_id", None)):
            self.__send(json.dumps({"code": -1, "msg": "need a dir id"}))
            return

        view_deleted = loaded_recv["data"].get("view_deleted", False)

        if loaded_recv["data"]["action"] == "recover":
            view_deleted = True  # 若要恢复文件，则必须有权访问被删除的文件

        if view_deleted:  # 如果启用 view_deleted 选项
            if not user.hasRights(("view_deleted",)):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        handle_cursor = self.db_cursor

        handle_cursor.execute(
            'SELECT `name`, `parent_id`, `access_rules`, `external_access`, `properties`, `state` \
                              FROM path_structures WHERE `id` = ? AND `type` = "dir";',
            (dir_id,),
        )

        result = handle_cursor.fetchall()

        # print(result)

        if len(result) > 1:
            raise ValueError("Invaild query result length")
        elif len(result) < 1:
            self.__send(json.dumps({"code": -1, "msg": "no such dir"}))
            return
        else:
            if (dir_state := json.loads(result[0][5]))["code"] == "deleted":
                # 如下，file_state 不一定是 file 的 state，但由于安全性原因只能先写这个判断
                if not view_deleted:
                    self.__send(json.dumps(self.RES_NOT_FOUND))
                    return

        parent_id = result[0][1]  # 文件夹的父级目录 ID

        if action in [
            "list",
            "delete",
            "permanently_delete",
            "rename",
            "recover",
            "move",
            "change_id",
        ]:
            # 鉴权
            if not self.verifyUserAccess(dir_id, action, user, _subcall=False):
                self.__send(json.dumps({"code": 403, "msg": "permission denied"}))
                self.log.logger.debug("权限校验失败：无权执行所请求的操作")
                return

            if action == "list":
                handle_cursor.execute(
                    "SELECT `id`, `name`, `type`, `properties`, `state` FROM path_structures WHERE `parent_id` = ?",
                    (dir_id,),
                )
                all_result = handle_cursor.fetchall()

                dir_result = dict()

                for i in all_result:
                    this_object_state = json.loads(i[4])

                    if this_object_state["code"] == "deleted":  # 如果已被删除
                        if not view_deleted:
                            continue

                    if not self.verifyUserAccess(
                        i[0], "read", user
                    ):  # 检查该目录下的文件是否有权访问，如无则隐藏
                        if self.config["security"]["hide_when_no_access"]:
                            continue
                        else:
                            pass

                    original_properties = json.loads(i[3])

                    filtered_properties = self.filterPathProperties(original_properties)

                    if i[2] == "file":
                        filtered_properties["size"] = self.getFileSize(i[0])

                    # print(i)
                    dir_result[i[0]] = {
                        "name": i[1],
                        "type": i[2],
                        "state": this_object_state,  # dict
                        "properties": filtered_properties,
                    }

                por_policy = Policies(
                    "permission_on_rootdir", self.db_conn, self.db_cursor
                )

                if parent_id:
                    if self.verifyUserAccess(
                        parent_id, "read", user
                    ):  # 检查是否有权访问父级目录
                        handle_cursor.execute(
                            "SELECT `name`, `type`, `properties` FROM path_structures WHERE `id` = ?",
                            (parent_id,),
                        )
                        parent_result = handle_cursor.fetchone()

                        parent_properties = json.loads(parent_result[2])

                        if parent_result[1] != "dir":
                            raise RuntimeError("父级目录并非一个文件夹")

                        dir_result[parent_id] = {
                            "name": parent_result[0],
                            "type": "dir",
                            "parent": True,
                            "properties": self.filterPathProperties(parent_properties),
                        }

                else:  # 如果父级目录是根目录，检查是否有权访问根目录
                    self.log.logger.debug(
                        f"目录 {dir_id} 的上级目录为根目录。正在检查用户是否有权访问根目录..."
                    )

                    por_access_rules = por_policy["rules"]["access_rules"]
                    por_external_access = por_policy["rules"]["external_access"]

                    if not self._verifyAccess(
                        user, "read", por_access_rules, por_external_access, True
                    ):
                        self.log.logger.debug("用户无权访问根目录")
                    else:
                        self.log.logger.debug("根目录鉴权成功")

                        dir_result[""] = {
                            "name": "<root directory>",
                            "type": "dir",
                            "parent": True,
                            "properties": {},
                            # "properties": self.filterPathProperties(parent_properties)
                        }

                self.__send(json.dumps({"code": 0, "dir_data": dir_result}))

            elif action == "delete":
                recycle_policy = Policies("recycle", self.db_conn, self.db_cursor)
                delete_after_marked_time = recycle_policy["deleteAfterMarked"]

                if dir_state["code"] == "deleted":
                    self.__send(
                        json.dumps(
                            {
                                "code": -1,
                                "msg": "The directory has been marked for deletion",
                            }
                        )
                    )
                    return

                succeeded, failed = self.deleteDir(
                    dir_id, user, delete_after=delete_after_marked_time
                )

                if failed:
                    response_code = -3  # 请求已经完成，但有错误
                else:
                    response_code = 0

                response = {
                    "code": response_code,
                    "msg": "request processed",
                    "data": {"succeeded": succeeded, "failed": failed},
                }

                self.__send(json.dumps(response))

            elif action == "permanently_delete":
                pass

            elif action == "rename":
                new_dirname = loaded_recv["data"].get("new_dirname", None)

                if not new_dirname:  # dirname 不能为空
                    self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
                    return

                if dir_state_code := dir_state["code"] != "ok":
                    if dir_state_code == "locked":
                        self.__send(
                            json.dumps(
                                {
                                    "code": -1,
                                    "msg": "directory is locked",
                                    "data": {
                                        "expire_time": dir_state.get("expire_time", 0)
                                    },
                                }
                            )
                        )
                        return

                handle_cursor.execute(
                    "UPDATE path_structures SET `name` = ? WHERE `id` = ?;",
                    (new_dirname, dir_id),
                )

                self.db_conn.commit()

                self.__send(json.dumps({"code": 0, "msg": "success"}))

            elif (
                action == "recover"
            ):  # 会恢复其下的所有内容，无论其是否因删除此文件夹而被删除
                if dir_state["code"] != "deleted":
                    self.__send(
                        json.dumps({"code": -1, "msg": "Directory is not deleted"})
                    )
                    return

                succeeded, failed = self.recoverDir(dir_id, user)

                if failed:
                    response_code = -3  # 请求已经完成，但有错误
                else:
                    response_code = 0

                response = {
                    "code": response_code,
                    "msg": "request processed",
                    "data": {"succeeded": succeeded, "failed": failed},
                }

                self.__send(json.dumps(response))

            elif action == "move":  # 基本同 operateFile 的判断
                new_parent_id = loaded_recv["data"].get("new_parent", None)

                if new_parent_id == None:  # 因为根目录的id为空
                    self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
                    return

                if new_parent_id == dir_id:
                    self.__send(
                        json.dumps(
                            {"code": -2, "msg": "一个目录的父级目录不能指向它自己"}
                        )
                    )
                    return

                # 判断新目录是否存在

                handle_cursor = self.db_cursor

                handle_cursor.execute(
                    "SELECT `type` FROM path_structures WHERE `id` = ?",
                    (new_parent_id,),
                )

                query_result = handle_cursor.fetchall()

                if len(query_result) == 0:
                    self.__send(
                        json.dumps({"code": 404, "msg": "没有找到请求的新目录"})
                    )
                    return
                elif len(query_result) != 1:
                    raise ValueError("意料之外的记录数量")

                if query_result[0][0] != "dir":
                    self.__send(json.dumps({"code": -1, "msg": "新的路径不是一个目录"}))
                    return

                # 调取原目录

                handle_cursor.execute(
                    "SELECT `parent_id` FROM path_structures WHERE `id` = ?", (dir_id,)
                )

                old_parent_result = handle_cursor.fetchone()

                old_parent_id = old_parent_result[0]

                if not self.verifyUserAccess(
                    new_parent_id, "write", user
                ) or not self.verifyUserAccess(old_parent_id, "delete", user):
                    # 移动操作实际上是向新目录写入文件，并删除旧目录文件

                    self.__send(json.dumps(self.RES_ACCESS_DENIED))
                    return

                # 执行操作

                handle_cursor.execute(
                    "UPDATE path_structures SET `parent_id` = ? WHERE `id` = ?;",
                    (new_parent_id, dir_id),
                )
                # 不需要对下级文件做其他操作

                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))

                return

            elif action == "change_id":
                if not user.hasRights(("change_id",)):
                    self.__send(json.dumps(self.RES_ACCESS_DENIED))
                    return

                new_id = loaded_recv["data"].get("new_id", None)

                if not new_id:
                    self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
                    return

                if new_id == dir_id:  # 如果和原ID一致，用于减少数据库开销
                    self.__send(json.dumps({"code": 0, "msg": "no changes made"}))
                    return

                # 判断新 ID 是否被使用

                handle_cursor = self.db_cursor

                handle_cursor.execute(
                    "SELECT `type` FROM path_structures WHERE `id` = ?", (new_id,)
                )

                result = handle_cursor.fetchall()

                if result:
                    self.__send(json.dumps({"code": -1, "msg": "id exists"}))
                    return

                # 执行操作

                handle_cursor.execute(
                    "UPDATE path_structures SET `id` = ? WHERE `id` = ?;",
                    (new_id, dir_id),
                )

                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))

                return

        else:
            self.__send(json.dumps(self.RES_BAD_REQUEST))

    @userOperationAuthWrapper
    def handle_createDir(self, loaded_recv, user: Users):
        if "data" not in loaded_recv:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        if not user.hasRights(("create_dir",)):  # 鉴权
            self.__send(json.dumps(self.RES_ACCESS_DENIED))
            return

        target_parent_id = loaded_recv["data"].get(
            "parent_id", ""
        )  # fallback to rootdir
        target_id = loaded_recv["data"].get("dir_id", None)
        new_dirname = loaded_recv["data"].get("name", None)

        if not new_dirname:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        if target_id:  # 自动生成
            if len(target_id) > 64:
                self.__send(json.dumps({"code": -1, "msg": "directory id too long"}))
                return
        else:
            target_id = secrets.token_hex(16)

        handle_cursor = self.db_cursor

        handle_cursor.execute(
            "SELECT 1 FROM path_structures WHERE `id` = ?", (target_id,)
        )

        query_result = handle_cursor.fetchall()

        if query_result:
            self.__send(
                json.dumps(
                    {
                        "code": -1,
                        "msg": "file or directory exists.",
                        "__hint__": "if you want to override a directory, use 'operateDir' instead.",
                    }
                )
            )
            return

        del query_result  # 清除

        if target_parent_id:  # 如果不是根目录
            handle_cursor.execute(
                "SELECT `type` FROM path_structures WHERE `id` = ?", (target_parent_id,)
            )

            dir_query_result = handle_cursor.fetchall()

            if not dir_query_result:
                self.__send(
                    json.dumps({"code": 404, "msg": "target directory not found"})
                )
                return
            elif len(dir_query_result) > 1:
                raise RuntimeError("数据库出现了不止一条同id的记录")

            if (d_id_type := dir_query_result[0][0]) != "dir":
                self.log.logger.debug(
                    f"用户试图请求在 id 为 {target_parent_id} 的目录下创建子目录，\
                                    但它事实上不是一个目录（{d_id_type}）"
                )
                self.__send(json.dumps({"code": -1, "msg": "not a directory"}))
                return

            if not self.verifyUserAccess(target_parent_id, "write", user):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        else:
            por_policy = Policies("permission_on_rootdir", self.db_conn, self.db_cursor)

            por_access_rules = por_policy["rules"]["access_rules"]
            por_external_access = por_policy["rules"]["external_access"]

            if not self._verifyAccess(
                user, "write", por_access_rules, por_external_access, True
            ):
                self.log.logger.debug("用户无权访问根目录")
                self.__send(self.RES_ACCESS_DENIED)
                return
            else:
                self.log.logger.debug("根目录鉴权成功")

        # 开始创建文件夹

        # 注册数据库条目

        handle_cursor.execute(
            "INSERT INTO path_structures \
                              (`id` , `name`, `owner` , `parent_id` , `type` , `revisions` , `access_rules`, `external_access`, `properties`, `state`) \
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (
                target_id,
                new_dirname,
                json.dumps((("user", user.username),)),
                target_parent_id,
                "dir",
                None,
                r"{}",
                r"{}",
                json.dumps({"created_time": time.time()}),
                json.dumps({"code": "ok", "expire_time": 0}),
            ),
        )

        self.db_conn.commit()

        self.__send(
            json.dumps(
                {"code": 0, "msg": "directory created", "data": {"dir_id": target_id}}
            )
        )

        return

    # =====================================

    #    -*- operateUser 部分 -*-

    #  该部分处理用户操作的相关请求。
    #  注意：这不包括创建用户的操作。

    # =====================================

    @userOperationAuthWrapper
    def handle_operateUser(self, loaded_recv, user: Users):
        handle_cursor = self.db_cursor

        if "data" not in loaded_recv:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        if not (action := loaded_recv["data"].get("action", None)):
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        username = loaded_recv["data"].get("username", user.username)

        if not username:
            self.__send(json.dumps({"code": -1, "msg": "need a username"}))

        elif username != user.username and action != "get_publickey":
            if not user.hasRights(("edit_other_users",)):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        dest_user = Users(username, self.db_conn, self.db_cursor)

        if not dest_user.ifExists():
            self.__send(json.dumps({"code": 404, "msg": "user not found"}))
            return

        dest_user.load()

        user_properties = dest_user.properties
        user_state = user_properties["state"]

        if action in [
            "set_nickname",
            "delete",  # done
            "passwd",  # done
            "set_rights",  # done
            "set_groups",  # done
            "set_username",  # done - not allowed
            "set_status",
            "set_publickey",  # done
            "get_publickey",  # done - TODO #13 单设备一公钥
        ]:
            # 因为这里的操作不是路径操作，故只能手动鉴权

            if action == "set_nickname":
                if not user.hasRights(("set_nickname",)):
                    self.__send(json.dumps(self.RES_ACCESS_DENIED))
                    return

                # if user.username != dest_user.username and not user.hasRights(("set_others",)):
                #     pass

                handle_cursor.execute(
                    "UPDATE `users` SET `nickname` = ? WHERE `username` = ?",
                    (dest_user.username,),
                )

                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))
                return

            elif action == "delete":
                if not user.hasRights(("delete_user",)):
                    self.__send(json.dumps(self.RES_ACCESS_DENIED))
                    return

                if dest_user.username == user.username:
                    self.__send(
                        json.dumps({"code": -1, "msg": "a user cannot delete itself"})
                    )
                    return

                ft_conn = sqlite3.connect(f"{self.root_abspath}/content/fqueue.db")
                ft_cursor = ft_conn.cursor()

                # 删除任务, 留下已完成的任务供查证
                # 或许可以改变 done 的值来标记文件 - 任务已取消？
                ft_cursor.execute(
                    "DELETE from ft_queue WHERE username = ? AND done = 0;",
                    (dest_user.username,),
                )
                ft_conn.commit()
                ft_conn.close()

                # 删除用户
                handle_cursor.execute(
                    "DELETE from `users` WHERE `username` = ?;", (dest_user.username,)
                )
                self.db_conn.commit()

                self.__send(json.dump(self.RES_OK))
                return

            elif action == "set_publickey":  # incomplete - does not support device_id
                new_publickey = loaded_recv["data"].get("publickey", None)
                if not new_publickey:
                    self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
                    return

                try:
                    RSA.import_key(new_publickey)
                except (ValueError, IndexError, TypeError):
                    self.__send(json.dumps({"code": -1, "msg": "not a vaild key"}))
                    return

                handle_cursor.execute(
                    "UPDATE `users` SET `publickey` = ? WHERE `username` = ?",
                    (new_publickey, dest_user.username),
                )
                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))
                return

            elif action == "get_publickey":
                if user.username != dest_user.username:
                    if not user.hasRights(("view_others_publickey",)):
                        self.__send(json.dumps(self.RES_ACCESS_DENIED))
                        return

                if dest_user.publickey:
                    self.__send(
                        json.dumps(
                            {
                                "code": 0,
                                "msg": "ok",
                                "data": {"publickey": dest_user.publickey},
                            }
                        )
                    )

                else:
                    self.__send(
                        json.dumps(
                            {"code": 404, "msg": "the user does not have a publickey"}
                        )
                    )

            elif action == "passwd":
                new_pwd = loaded_recv["data"].get("new_pwd", None)
                if not new_pwd:
                    self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
                    return

                # 随机生成8位salt
                alphabet = string.ascii_letters + string.digits
                salt = "".join(secrets.choice(alphabet) for i in range(8))  # 安全化

                __first = hashlib.sha256(new_pwd.encode()).hexdigest()
                __second_obj = hashlib.sha256()
                __second_obj.update((__first + salt).encode())

                salted_pwd = __second_obj.hexdigest()

                handle_cursor.execute(
                    "UPDATE `users` SET `hash` = ?, `salt` = ? WHERE `username` = ?",
                    (salted_pwd, salt, dest_user.username),
                )

                self.db_conn.commit()

                self.__send(json.dumps(self.RES_OK))

            elif action == "set_username":
                self.__send(json.dumps({"code": -1, "msg": "not allowed"}))
                return

            elif action == "set_groups":
                if not user.hasRights(("set_usergroups",)):
                    self.__send(json.dumps(self.RES_ACCESS_DENIED))
                    return

                new_groups = loaded_recv["data"].get("new_groups", None)

                if new_groups == None:
                    self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
                    return

                if not StructureValidater.checkGroupStructure(new_groups)[0]:
                    self.__send(
                        json.dumps({"code": -1, "msg": "invaild data structure"})
                    )
                    return

                handle_cursor.execute(
                    "UPDATE `users` SET `groups` = ? WHERE `username` = ?",
                    (json.dumps(new_groups), dest_user.username),
                )

                self.__send(json.dumps(self.RES_OK))

            elif action == "set_rights":
                if not user.hasRights(("set_userrights",)):
                    self.__send(json.dumps(self.RES_ACCESS_DENIED))
                    return

                new_rights = loaded_recv["data"].get("new_rights", None)

                if new_rights == None:
                    self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
                    return

                if not StructureValidater.checkRightStructure(new_rights)[0]:
                    self.__send(
                        json.dumps({"code": -1, "msg": "invaild data structure"})
                    )
                    return

                handle_cursor.execute(
                    "UPDATE `users` SET `rights` = ? WHERE `username` = ?",
                    (json.dumps(new_rights), dest_user.username),
                )

                self.__send(json.dumps(self.RES_OK))

        else:
            self.__send(json.dumps(self.RES_BAD_REQUEST))

    @userOperationAuthWrapper
    def handle_getFileRevisions(self, loaded_recv, user: Users):
        try:
            file_id: str = loaded_recv["data"]["file_id"]
            view_deleted: bool = bool(loaded_recv["data"].get("view_deleted", False))
            reverse: bool = bool(
                loaded_recv["data"].get("reverse", True)
            )  # 反序，默认开启 - 按从新到旧排序
            item_range: tuple[int, int] = tuple(
                loaded_recv["data"].get("item_range", ())
            )
        except KeyError:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return

        # 判断文件是否存在
        if not self._hasFileRecord(file_id):
            self.__send(json.dumps(self.RES_NOT_FOUND))
            return

        if not self.verifyUserAccess(
            file_id, "read", user
        ):  # 目前仅要求用户具有 read 权限，未来可能细化
            self.__send(json.dumps(self.RES_ACCESS_DENIED))
            return

        if view_deleted:
            if not user.hasRights(("view_deleted",)):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        if not item_range:
            item_range = (0, 10)

        if (
            len(item_range) != 2
            or not isinstance(item_range[0], int)
            or not isinstance(item_range[1], int)
            or item_range[0] > item_range[1]
            or item_range < (0, 1)
        ):  # item_range 必须前者小于后者，如需倒序使用 reverse 函数
            self.__send(json.dumps({"code": 400, "msg": "invaild range syntax"}))
            return

        if (max_count := item_range[1] - item_range[0]) > 50:
            self.__send(
                json.dumps({"code": 400, "msg": "max revision count out of range"})
            )
            return

        handle_cursor = self.db_cursor

        handle_cursor.execute(
            "SELECT `type`, `revisions` FROM path_structures WHERE `id` = ?", (file_id,)
        )
        query_result = handle_cursor.fetchone()

        if not query_result:
            self.__send(json.dumps(self.RES_NOT_FOUND))
            return

        if query_result[0] != "file":
            self.__send(json.dumps({"code": -1, "msg": "not a file"}))
            return

        query_revisions = json.loads(query_result[1])

        # 开始剔除不可用 revisions

        # 排序
        sorted_revisions: list[tuple] = sorted(
            query_revisions.items(), key=lambda i: i[1]["time"], reverse=reverse
        )

        final_revisions = {}

        revisions_count = len(sorted_revisions)

        _i = 0  # 总的循环次数，不能大于 revisions_count
        _k = 0  # 成功的次数，不应大于 max_count

        while _i < revisions_count and _k < (
            max_count if max_count <= revisions_count else revisions_count
        ):
            _i += 1  # _i 加了1，此时才正确表示本次循环的序号

            per_revision = sorted_revisions[item_range[0] + _i - 1]

            if per_revision[1]["state"]["code"] == "deleted" and not view_deleted:
                continue

            this_revision_id, this_revision_data = per_revision

            if self._verifyAccess(
                user,
                "read",
                this_revision_data["access_rules"],
                this_revision_data["external_access"],
            ):
                final_revisions[this_revision_id] = this_revision_data
                _k += 1

        self.__send(
            json.dumps({"code": 0, "msg": "ok", "data": {"revisions": final_revisions}})
        )
