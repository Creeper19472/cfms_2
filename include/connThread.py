# connThread.py

from functools import wraps
import os
import datetime
import secrets
import hashlib
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
from include.bulitin_class._documents import Documents # 已弃用
from include.bulitin_class.policies import Policies

class PendingWriteFileError(Exception):
    pass


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
            e.add_note("看起来线程内部的运行出现了问题。将关闭到客户端的连接。")
            target_class.log.logger.fatal(f"{self.name}: 看起来线程内部的运行出现了问题：", exc_info=True)
            target_class.conn.close()
            sys.exit()

class ConnHandler():

    # 定义经常使用的响应内容

    RES_MISSING_ARGUMENT = {
        "code": -1,
        "msg": "missing necessary arguments"
    }

    RES_ACCESS_DENIED = {
        "code": 403,
        "msg": "forbidden"
    }

    RES_NOT_FOUND = {
        "code": 404,
        "msg": "not found"
    }

    RES_INTERNAL_ERROR = {
        "code": 500,
        "msg": "internal server error"
    }

    RES_OK = {
        "code": 0,
        "msg": "ok"
    }


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

        self.log.logger.debug(f"AES Key: {decrypted_data}")

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
                self.log.logger.info("Connection closed")
                sys.exit()

            # print(f"recv: {recv}")

            try:
                loaded_recv = json.loads(recv)
            except Exception as e:
                self.log.logger.debug(f"Error when loading recv: {e}")
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "invaild request format"
                }))
                continue

            client_api_version = loaded_recv.get("version", None)

            # 判断 API 版本
            if not client_api_version:
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "API version is not given"
                }))
                continue


            if client_api_version == 1:
                self.handle_v1(loaded_recv)
            else: # 目前仅支持 V1
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "unsupported API version"
                }))
                continue

    def _verifyAccess(self, user: Users, action, access_rules: dict, external_access: dict, check_deny=True):
        if not access_rules: # fix #7
            return True # fallback
        
        if user.hasRights(("super_access",)):
            return True # 放行超级权限，避免管理员被锁定在外

        # 确认是否满足 deny 规则
        if check_deny:
            # print(access_rules)
            all_deny_rules = access_rules.get("deny", {})

            this_action_deny_value = all_deny_rules.get(action, {})
            # print(this_action_deny_value)

            this_deny_groups = this_action_deny_value.get("groups", {})
            this_deny_users = this_action_deny_value.get("users", {})
            this_deny_rules = this_action_deny_value.get("rules", [])

            _deny_expire_time = None # 置空

            if user.username in this_deny_users:
                if not (_deny_expire_time:=this_deny_users[user.username].get("expire", 0)): # 如果expire为0
                    return False
                if _deny_expire_time > time.time(): # 如果尚未过期
                    return False
                
            _deny_expire_time = None # 置空

            for i in user.groups:
                if i in this_deny_groups:
                    if not (_deny_expire_time:=this_deny_groups[i].get("expire", 0)): # 如果expire为0
                        return False
                    if _deny_expire_time > time.time(): # 如果尚未过期
                        return False
                    
            del _deny_expire_time

            if this_deny_rules: # 必须存在才会判断
                if user.ifMatchRules(this_deny_rules):
                    return False

        # access_rules 包括所有规则
        if user.ifMatchRules(access_rules[action]):
            return True
        
        if external_access:
        
            for i in external_access["groups"]:
                if action not in (i_dict:=external_access["groups"][i]).keys():
                    continue
                if (not (expire_time:=i_dict[action].get("expire", 0))) or (expire_time >= time.time()): # 如果用户组拥有的权限尚未到期
                    if user.hasGroups((i,)): # 如果用户存在于此用户组
                        return True
                    
            if user.username in external_access["users"].keys(): # 如果用户在字典中有记录
                if action in (user_action_dict:=external_access["users"][user.username]).keys(): # 如果请求操作在用户的字典中有记录
                    if (not (expire_time:=user_action_dict[action].get("expire", 0))) or (expire_time >= time.time()): # 如果用户拥有的权限尚未到期
                        return True
                
        return False
    
    def createFileTask(self, file_id, task_id=None, operation="read", expire_time=None, force_write=False):
        fqueue_db = sqlite3.connect(f"{self.root_abspath}/content/fqueue.db")

        fq_cur = fqueue_db.cursor()

        if not task_id:
            task_id = secrets.token_hex(64)

        if expire_time == None:
            expire_time = time.time() + 3600 # by default
        
        token_hash = secrets.token_hex(64)
        token_salt = secrets.token_hex(16)

        token_hash_sha256 = hashlib.sha256(token_hash.encode()).hexdigest()
        final_token_hash_obj = hashlib.sha256()
        final_token_hash_obj.update((token_hash_sha256+token_salt).encode())

        final_token_hash = final_token_hash_obj.hexdigest()

        token_to_store = (final_token_hash, token_salt)

        # fake_id, fake_dir(set to task_id)
        fake_id = secrets.token_hex(16)
        fake_dir = task_id[32:]

        if operation == "write":
            fq_cur.execute('SELECT * FROM ft_queue WHERE file_id = ? AND operation = "write" AND done = 0;', (file_id, ))
            query_result = fq_cur.fetchall()

            if query_result and not force_write:
                raise PendingWriteFileError("文件存在一需要写入的任务，且该任务尚未完成")

        fq_cur.execute("INSERT INTO ft_queue (task_id, operation, token, fake_id, fake_dir, file_id, expire_time, done) \
                        VALUES ( ?, ?, ?, ?, ?, ?, ?, 0 );", (task_id, operation, json.dumps(token_to_store),\
                                                            fake_id, fake_dir, file_id, expire_time))
        
        fqueue_db.commit()
        fqueue_db.close()

        return task_id, token_hash_sha256, fake_id, expire_time
    
    def permanentlyDeleteFile(self, fake_path_id):
        g_cur = self.db_conn.cursor()

        # 查询文件信息

        g_cur.execute("SELECT type , file_id FROM path_structures WHERE id = ?", (fake_path_id,))
        query_result = g_cur.fetchall()

        if len(query_result) == 0:
            raise FileNotFoundError
        elif len(query_result) > 1:
            raise ValueError("在查询表 path_structures 时发现不止一条同路径 id 的记录")
        
        got_type, index_file_id = query_result[0]

        if got_type != "file":
            raise TypeError("删除的必须是一个文件")
        
        # 查询 document_indexes 表

        g_cur.execute("SELECT abspath FROM document_indexes WHERE id = ?", (index_file_id,))

        index_query_result = g_cur.fetchall()

        if len(index_query_result) == 0:
            raise FileNotFoundError(f"未发现在 path_structures 中所指定的文件 id '{index_file_id}' 的记录")
        elif len(index_query_result) > 1:
            raise ValueError("在查询表 document_indexes 时发现不止一条同 id 的记录")
        
        file_abspath = index_query_result[0][0]

        if not file_abspath:
            raise ValueError("file_abspath 必须有值")

        # 删除表记录

        g_cur.execute("DELETE from document_indexes where id = ?;", (index_file_id,))
        g_cur.execute("DELETE from path_structures where id = ?;", (fake_path_id,))

        self.db_conn.commit()

        # 移除所有传输任务列表

        fq_db = sqlite3.connect(f"{self.root_abspath}/content/fqueue.db")
        fq_cur = fq_db.cursor()

        fq_cur.execute("DELETE from ft_queue WHERE file_id = ?", (index_file_id,)) #  AND done = 0
        fq_db.commit()
        fq_db.close()

        # 删除真实文件

        os.remove(file_abspath)

        return True

    def filterPathProperties(self, properties: dict):
        result = properties
        
        # TODO #11

        return result
    
    def userOperationAuthWrapper(self, func):
        @wraps(func)
        def _wrapper():
            return func
        return _wrapper


    def verifyUserAccess(self, id, action, user: Users, checkdeny=True, _subcall=False):
        """
        用户鉴权函数。
        用于逐级检查用户是否拥有访问权限，若发生任意无情况即返回 False
        """
        self.log.logger.debug(f"verifyUserAccess(): 正在对 用户 {user.username} 访问 id: {id} 的请求 进行鉴权")

        db_cur = self.db_conn.cursor()
        db_cur.execute("SELECT parent_id, access_rules, external_access, type FROM path_structures WHERE id = ?", (id,))

        result = db_cur.fetchall()

        assert len(result) == 1

        por_policy = Policies("permission_on_rootdir", self.db_conn)

        access_rules = json.loads(result[0][1])
        external_access = json.loads(result[0][2])

        if _subcall: # 如果来自子路径调用（这应该表示本路径是一个文件夹）
            self.log.logger.debug("_subcall 为真")

            if result[0][3] != "dir":
                raise TypeError("Not a directory: does not support _subcall")

            if not access_rules.get("__subinherit__", True): # 如果设置为下层不继承（对于文件应该无此设置）
                self.log.logger.debug("本层设置为下层不继承，返回为真")
                return True

        if not (action in (_noinherit:=access_rules.get("__noinherit__", []))) and not ("all" in _noinherit): # 判断该目录是否继承上层设置
                
            if not (f"deny_{action}" in (_noinherit)) \
                and (not "deny" in _noinherit) and checkdeny:
                # 1. 本层路径继承上层设置；
                # 2. 本函数的调用者要求检查 deny；
                self.log.logger.debug("将检查上级目录的 deny 规则")
                parent_checkdeny = True
            else:
                parent_checkdeny = False


            if (parent:=result[0][0]): # 如果仍有父级

                self.log.logger.debug(f"正在检查其父目录 {parent} 的权限...")
                if not self.verifyUserAccess(parent, action, user, \
                                            checkdeny = parent_checkdeny, _subcall=True):
                    return False
                self.log.logger.debug("完毕，无事发生。")

            elif por_policy["inherit_by_subdirectory"]: # 如果没有父级（是根目录）
                self.log.logger.debug("PoR_IbS 已激活，正在检查用户对于根目录的权限...")

                por_access_rules = por_policy["rules"]["access_rules"]
                por_external_access = por_policy["rules"]["external_access"]

                if not self._verifyAccess(user, action, por_access_rules, por_external_access, parent_checkdeny):
                    self.log.logger.debug("PoR 鉴权失败")
                    return False
                else:
                    self.log.logger.debug("PoR 鉴权成功")

        else:
            self.log.logger.debug("请求操作在该路径上被设置为不继承上层设置，跳过")
            

        self.log.logger.debug(f"所有访问规则和附加权限记录：{access_rules}, {external_access}")

        if self._verifyAccess(user, action, access_rules, external_access, check_deny=checkdeny):
            self.log.logger.debug(f"verifyUserAccess(): 用户 {user.username} 对于 id: {id} 的请求 鉴权成功")
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

            return # 如果不返回，那么下面的判断就会被执行了
        
        elif loaded_recv["request"] == "disconnect":
            self.__send("Goodbye")
            self.conn.close()

            self.log.logger.info("客户端断开连接")

            sys.exit() # 退出线程

        
        # 以下的所有请求都应该是需要鉴权的，如果不是请放在上面
        # 如果需要与以下鉴权过程不同的鉴权请放在上面处理
        # 上面部分的每个判断都应该有 return

        ### 获取 auth 标头

        try:
            attached_token = loaded_recv["auth"]["token"]
            attached_username = loaded_recv["auth"]["username"]
        except KeyError:
            self.log.logger.debug("请求无效：认证数据不完整或缺失")
            self.__send(json.dumps({
                "code": -1,
                "msg": "no full authentication data provided"
            }))
            return

        ### 结束

        if loaded_recv["request"] == "refreshToken":

            self.log.logger.debug("收到客户端的 refreshToken 请求")

            self.handle_refreshToken(attached_username, attached_token)

        elif loaded_recv["request"] == "operateFile":
            
            ### 通用用户令牌鉴权开始
            
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
            
            user.load()

            ### 结束

            self.handle_operateFile(loaded_recv, user)

        elif loaded_recv["request"] == "getDir":
            
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
            
            user.load()
            
            self.handle_getDir(loaded_recv, user)

        elif loaded_recv["request"] == "getRootDir":

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
            
            user.load()
            
            self.handle_getRootDir(loaded_recv, user)

        elif loaded_recv["request"] == "getPolicy":

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
            
            user.load()
            
            self.handle_getPolicy(loaded_recv, user)

        elif loaded_recv["request"] == "getAvatar":

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
            
            user.load()
            
            self.handle_getAvatar(loaded_recv, user)

        elif loaded_recv["request"] == "uploadFile":
            
            # TODO #12 重复验证过程加入装饰器
            
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
            
            user.load()

            self.handle_uploadFile(loaded_recv, user)

        elif loaded_recv["request"] == "createUser":

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
            
            user.load()

            self.handle_createUser(loaded_recv, user)




        else:
            self.__send(json.dumps({
                "code": -1,
                "msg": "unknown request"
            }))


            
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

                user_auth_policy = Policies("user_auth", self.db_conn)
                sleep_for_fail = user_auth_policy["sleep_when_login_fail"]

                if sleep_for_fail:
                    self.log.logger.debug(f"正根据登录策略睡眠 {sleep_for_fail} 秒")
                    time.sleep(sleep_for_fail)

                if self.config["security"]["show_login_fail_details"]:
                    fail_msg = "password incorrect"
                else:
                    fail_msg = "username or password incorrect"

                self.__send(json.dumps({
                    "code": 401,
                    "msg": fail_msg
                })
                )
        else:
            if self.config["security"]["show_login_fail_details"]:
                fail_msg = "user does not exist"
            else:
                fail_msg = "username or password incorrect"

            user_auth_policy = Policies("user_auth", self.db_conn)
            sleep_for_fail = user_auth_policy["sleep_when_login_fail"]

            if sleep_for_fail:
                self.log.logger.debug(f"正根据登录策略睡眠 {sleep_for_fail} 秒")
                time.sleep(sleep_for_fail)

            self.__send(json.dumps({
                "code": 401,
                "msg": fail_msg
            })
            )

    def handle_logout(self):
        pass


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

    def handle_getDir(self, recv, user: object):
        path_id = recv["data"].get("id")

        if not path_id:
            self.__send(json.dumps({
                "code": -1,
                "msg": "no path_id provided"
            }))

        handle_cursor = self.db_conn.cursor()

        handle_cursor.execute("SELECT type, parent_id FROM path_structures WHERE id = ?" , (path_id,))

        result = handle_cursor.fetchone()

        if result:
            tg_type = result[0]
            parent_id = result[1]
        else:
            self.__send(json.dumps({
                    "code": -1,
                    "msg": "no such file or directory"
                }))
            return
        
        del result
        
        if tg_type == "file":
            self.__send(json.dumps({
                    "code": -1,
                    "msg": "type 'file' does not have a dir function"
                }))
            return
        
        elif tg_type == "dir":
            if not self.verifyUserAccess(path_id, "read", user):
                self.__send(json.dumps({
                    "code": 403,
                    "msg": "permission denied"
                }))
                self.log.logger.debug("权限校验失败：无权访问")
                return
            

            handle_cursor.execute("SELECT id, name, type, properties FROM path_structures WHERE parent_id = ?" , (path_id,))
            all_result = handle_cursor.fetchall()

            dir_result = dict()

            for i in all_result:

                if not self.verifyUserAccess(i[0], "read", user): # 检查该目录下的文件是否有权访问，如无则隐藏
                    if self.config["security"]["hide_when_no_access"]:
                        continue
                    else:
                        pass

                original_properties = json.loads(i[3])

                # print(i)
                dir_result[i[0]] = {
                    "name": i[1],
                    "type": i[2],
                    "properties": self.filterPathProperties(original_properties)
                }

            por_policy = Policies("permission_on_rootdir", self.db_conn)

            if parent_id:

                if self.verifyUserAccess(parent_id, "read", user): # 检查是否有权访问父级目录
                    handle_cursor.execute("SELECT name, type, properties FROM path_structures WHERE parent_id = ?" , (path_id,))
                    parent_result = handle_cursor.fetchone()

                    parent_properties = json.loads(parent_result[2])

                    assert parent_result[1] == "dir"

                    dir_result[parent_id] = {
                        "name": parent_result[0],
                        "type": "dir",
                        "parent": True,
                        "properties": self.filterPathProperties(parent_properties)
                    }

            else: # 如果父级目录是根目录，检查是否有权访问根目录
                self.log.logger.debug(f"目录 {path_id} 的上级目录为根目录。正在检查用户是否有权访问根目录...")

                por_access_rules = por_policy["rules"]["access_rules"]
                por_external_access = por_policy["rules"]["external_access"]

                if not self._verifyAccess(user, "read", por_access_rules, por_external_access, True):
                    self.log.logger.debug("用户无权访问根目录")
                else:
                    self.log.logger.debug("根目录鉴权成功")

                    dir_result[""] = {
                        "name": "<root directory>",
                        "type": "dir",
                        "parent": True,
                        "properties": {}
                        # "properties": self.filterPathProperties(parent_properties)
                    }


            self.__send(json.dumps({
                "code": 0,
                "dir_data": dir_result
            }))

        else:
            self.log.logger.error(f"错误：数据库中 path_id 为 {path_id} 的条目的 type 为意料之外的值： {tg_type}")
            self.__send(json.dumps({
                "code": 500,
                "msg": "internal server error"
            }))

    def handle_getRootDir(self, loaded_recv, user: Users):
        por_policy = Policies("permission_on_rootdir", self.db_conn)

        por_access_rules = por_policy["rules"]["access_rules"]
        por_external_access = por_policy["rules"]["external_access"]

        if not self._verifyAccess(user, "read", por_access_rules, por_external_access, True):
            self.log.logger.debug("用户无权访问根目录")
            self.__send(json.dumps({
                "code": 403,
                "msg": "forbidden"
            }))
            return
        else:
            self.log.logger.debug("根目录鉴权成功")

        handle_cursor = self.db_conn.cursor()

        handle_cursor.execute("SELECT id, name, type, properties FROM path_structures WHERE parent_id = ?" , ("",))
        all_result = handle_cursor.fetchall()

        dir_result = dict()

        for i in all_result:

            if not self.verifyUserAccess(i[0], "read", user): # 检查该目录下的文件是否有权访问，如无则隐藏
                if self.config["security"]["hide_when_no_access"]:
                    continue
                else:
                    pass

            original_properties = json.loads(i[3])

            # print(i)
            dir_result[i[0]] = {
                "name": i[1],
                "type": i[2],
                "properties": self.filterPathProperties(original_properties)
            }

        self.__send(json.dumps({
                "code": 0,
                "dir_data": dir_result
            }))
        
        return




    def handle_getPolicy(self, loaded_recv, user: Users):
        req_policy_id = loaded_recv["data"]["policy_id"]

        action = "read" # "getPolicy"，所以目前 action 就是 read

        handle_cursor = self.db_conn.cursor()
        handle_cursor.execute("SELECT content, access_rules, external_access FROM policies WHERE id = ?", (req_policy_id,))

        fetched = handle_cursor.fetchone()
        # 不是很想再写判断是否有重复ID的逻辑，反正出了问题看着办吧，这不是我要考虑的事

        if not fetched: # does not exist
            self.__send(json.dumps({
                "code": 404,
                "msg": "the policy you've requested does not exist"
            }))
            return

        content = json.loads(fetched[0])
        access_rules = json.loads(fetched[1])
        external_access = json.loads(fetched[2])

        if not self._verifyAccess(user, action, access_rules, external_access):
            self.__send(json.dumps({
                "code": 403,
                "msg": "forbidden"
            }))
        else:
            self.__send(json.dumps({
                "code": 0,
                "data": content
            }))

        return


    def handle_getAvatar(self, loaded_recv, user: Users):
        if not (avatar_username:=loaded_recv["data"].get("username")):
            self.__send(json.dumps({
                "code": -1,
                "msg": "needs a username"
            }))
            return
        
        get_avatar_user = Users(avatar_username, self.db_conn)

        if not get_avatar_user.ifExists():
            self.log.logger.debug(f"用户 {user.username} 试图请求帐户 {avatar_username} 的头像，但这个用户并不存在。")
            self.__send(json.dumps(
                {
                    "code": 404,
                    "msg": "not found"
                }
            ))
            return

        avatar_policy = Policies("avatars", self.db_conn)
        
        ### TODO #9 增加用户权限对头像获取权限的支持 - done

        gau_access_rules = get_avatar_user["publicity"].get("access_rules", {})
        gau_external_access = get_avatar_user["publicity"].get("external_access", {})

        if get_avatar_user["publicity"].get("restricted", False):
            if (not avatar_policy["allow_access_without_permission"])\
            and (not self._verifyAccess(user, "read", gau_access_rules, gau_external_access))\
            and (not user.hasRights(("super_useravatar",))):
                self.__send(json.dumps({
                    "code": 403,
                    "msg": "forbidden"
                }))
                return
            
        if (avatar_file_id:=get_avatar_user["avatar"].get("file_id", None)):
            task_id, task_token, t_filename = self.createFileTask(avatar_file_id)
            self.__send(json.dumps({
                "code": 0,
                "msg": "ok",
                "data": {
                    "task_id": task_id,
                    "task_token": task_token,
                    "t_filename": t_filename
                }
            }))
        else:
            if (default_avatar_id:=avatar_policy["default_avatar"]):
                task_id, task_token, t_filename, expire_time = self.createFileTask(default_avatar_id)

                self.log.logger.debug(f"用户 {user.username} 请求帐户 {avatar_username} 的头像，返回为默认头像。")

                self.__send(json.dumps({
                    "code": 0,
                    "msg": "ok",
                    "data": {
                        "task_id": task_id,
                        "task_token": task_token,
                        "t_filename": t_filename,
                        "expire_time": expire_time
                    }
                }))
            else:
                self.log.logger.debug(f"用户 {user.username} 试图请求帐户 {avatar_username} 的头像，但用户未设置头像，且策略指定的默认头像为空。")
                self.__send(json.dumps({
                    "code": 404,
                    "msg": "not found",
                    "data": {}
                }))

    def handle_uploadFile(self, loaded_recv, user: Users):

        if "data" not in loaded_recv:
            self.__send(json.dumps({
                self.RES_MISSING_ARGUMENT
            }))

        target_directory_id = loaded_recv["data"].get("directory_id", "") # fallback to rootdir
        target_file_path_id = loaded_recv["data"].get("file_id", None)
        target_filename = loaded_recv["data"].get("filename", f"Untitled-{int(time.time())}")

        if not target_file_path_id:
            self.__send(json.dumps(
                self.RES_MISSING_ARGUMENT
            ))
            return
        
        handle_cursor = self.db_conn.cursor()

        handle_cursor.execute("SELECT * FROM path_structures WHERE id = ?", (target_file_path_id,))

        query_result = handle_cursor.fetchall()

        if query_result:
            self.__send(json.dumps({
                "code": -1,
                "msg": "file or directory exists.",
                "__hint__": "if you want to override a file, use 'operateFile' instead."
            }))
            return
        
        del query_result # 清除

        if target_directory_id: # 如果不是根目录

            handle_cursor.execute("SELECT type FROM path_structures WHERE id = ?", (target_directory_id,))

            dir_query_result = handle_cursor.fetchall()

            if not dir_query_result:
                self.__send(json.dumps({
                    "code": 404,
                    "msg": "target directory not found"
                }))
                return
            elif len(dir_query_result) >= 1:
                raise RuntimeError("数据库出现了不止一条同id的记录")
            
            if (d_id_type:=dir_query_result[0][0]) != "dir":
                self.log.logger.debug(f"用户试图请求在 id 为 {target_directory_id} 的目录下创建文件，\
                                    但它事实上不是一个目录（{d_id_type}）")
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "not a directory"
                }))
                return
            
            if not self.verifyUserAccess(target_directory_id, "write", user):
                self.__send(json.dumps(
                    self.RES_ACCESS_DENIED
                ))
                return
            
        else:
            por_policy = Policies("permission_on_rootdir", self.db_conn)

            por_access_rules = por_policy["rules"]["access_rules"]
            por_external_access = por_policy["rules"]["external_access"]

            if not self._verifyAccess(user, "write", por_access_rules, por_external_access, True):
                self.log.logger.debug("用户无权访问根目录")
                self.__send(self.RES_ACCESS_DENIED)
                return
            else:
                self.log.logger.debug("根目录鉴权成功")

            
        
        # 开始创建文件

        index_file_id = secrets.token_hex(64) # 存储在 document_indexes 中
        real_filename = secrets.token_hex(16)

        today = datetime.date.today()

        destination_path = f"{self.root_abspath}/content/files/{today.year}/{today.month}"

        os.makedirs(destination_path, exist_ok=True) # 即使文件夹已存在也加以继续

        with open(f"{destination_path}/{real_filename}", "w") as new_file:
            pass

        # 注册数据库条目

        handle_cursor.execute("INSERT INTO document_indexes (id, abspath) VALUES (?, ?)", \
                              (index_file_id, destination_path+"/"+real_filename))
        
        handle_cursor.execute("INSERT INTO path_structures \
                              (id , name , owner , parent_id , type , file_id , access_rules, external_access, properties, state) \
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              (target_file_path_id, target_filename, json.dumps((("user", user.username),)), target_directory_id, 
                               "file", index_file_id, r"{}", r"{}", json.dumps({
                                   "created_time": time.time()
                               }), json.dumps({
                                   "code": "ok",
                                   "expire_time": 0
                               }) ))
        
        self.db_conn.commit()
        handle_cursor.close()

        # 创建任务
        task_id, task_token, t_filename, expire_time = self.createFileTask(index_file_id, operation="write")

        self.__send(json.dumps({
            "code": 0,
            "msg": "file created",
            "data": {
                "task_id": task_id,
                "task_token": task_token,
                "t_filename": t_filename,
                "expire_time": expire_time
            }
        }))

        return

    def handle_operateFile(self, loaded_recv, user: Users):
        
        if "data" not in loaded_recv:
            self.__send(json.dumps(
                self.RES_MISSING_ARGUMENT
            ))
            return
        
        if not loaded_recv["data"].get("action", None):
            self.__send(json.dumps(
                self.RES_MISSING_ARGUMENT
            ))
            return


        file_id = loaded_recv["data"].get("file_id", None) # 伪路径文件 ID
        view_deleted = loaded_recv["data"].get("view_deleted", False)
        
        if not file_id:
            self.__send(json.dumps(
                self.RES_MISSING_ARGUMENT
            ))
            return
        
        if loaded_recv["data"]["action"] == "recover":
            view_deleted = True # 若要恢复文件，则必须有权访问被删除的文件
        
        if view_deleted: # 如果启用 view_deleted 选项
            if not user.hasRights(("view_deleted",)):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return

        handle_cursor = self.db_conn.cursor()

        handle_cursor.execute("SELECT name, parent_id, type, file_id, access_rules, external_access, properties, state \
                              FROM path_structures WHERE id = ?", \
                              (file_id,))
        
        result = handle_cursor.fetchall()

        # print(result)

        if len(result) > 1:
            raise ValueError("Invaild query result length")
        elif len(result) < 1:
            self.__send(json.dumps({
                    "code": -1,
                    "msg": "no such file"
                }))
            return
        else:
            if (file_state:=json.loads(result[0][7]))["code"] == "deleted": 
                # 如下，file_state 不一定是 file 的 state，但由于安全性原因只能先写这个判断
                if not view_deleted:
                    self.__send(
                        json.dumps(self.RES_NOT_FOUND)
                    )
                    return

            if result[0][2] != "file":
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "not a file"
                }))
                return
            
            req_action = loaded_recv["data"]["action"]

            self.log.logger.debug(f"请求对文件的操作：{req_action}")

            if req_action in ["read", "write", "rename", "delete", "permanently_delete", "recover"]:

                # 注意：write 操作仅支持覆盖，创建请使用 uploadFile

                if not self.verifyUserAccess(file_id, req_action, user, _subcall = False):
                    self.__send(json.dumps({
                        "code": 403,
                        "msg": "permission denied"
                    }))
                    self.log.logger.debug("权限校验失败：无权执行所请求的操作")
                    return
                
                query_file_id = result[0][3]
                
                if req_action == "read":
                    # 权限检查已在上一步完成

                    task_id, task_token, fake_file_id, expire_time = \
                        self.createFileTask(query_file_id, operation="read", expire_time=time.time()+3600)

                    response = {
                        "code": 0,
                        "msg": "ok",
                        "data": {
                            "task_id": task_id,
                            "task_token": task_token, # original hash after sha256
                            "expire_time": expire_time,
                            "t_filename": fake_file_id
                        }
                    }

                    self.__send(json.dumps(response))

                
                elif req_action == "write":

                    if file_state_code:=file_state["code"] != "ok":
                        if file_state_code == "locked":
                            self.__send(json.dumps({
                                "code": -1,
                                "msg": "文件已锁定，请先解锁",
                                "data": {
                                    "expire_time": file_state.get("expire_time", 0)
                                }
                            }))
                            
                        elif file_state_code == "deleted":
                            self.__send(json.dumps({
                                "code": -1,
                                "msg": "文件已被标记为删除，请先恢复",
                                "data": {
                                    "expire_time": file_state.get("expire_time", 0)
                                }
                            }))
                            
                        else:
                            self.__send(json.dumps({
                                "code": -1,
                                "msg": "文件状态异常"
                            }))
                            
                        return
                    
                    try:
                        task_id, task_token, fake_file_id, expire_time = \
                            self.createFileTask(query_file_id, operation="write", expire_time=time.time()+3600)
                    except PendingWriteFileError:
                        self.__send(json.dumps({
                            "code": -1,
                            "msg": "文件正在使用中"
                        }))
                        return

                    response = {
                        "code": 0,
                        "msg": "ok",
                        "data": {
                            "task_id": task_id,
                            "task_token": task_token, # original hash after sha256
                            "expire_time": expire_time,
                            "t_filename": fake_file_id # 这个ID是客户端上传文件时应当使用的文件名
                        }
                    }

                    self.__send(json.dumps(response))

                
                elif req_action == "rename":

                    try:
                        new_filename = loaded_recv["data"]["new_filename"]
                    except ValueError:
                        self.__send(json.dumps({
                            "code": -1,
                            "msg": "not all arguments provided"
                        }))
                        return
                    
                    # if file_state_code:=file_state["code"] != "ok":
                    #     if file_state_code == "locked":
                    #         self.__send(json.dumps({
                    #             "code": -1,
                    #             "msg": "文件已锁定，请先解锁",
                    #             "data": {
                    #                 "expire_time": file_state.get("expire_time", 0)
                    #             }
                    #         }))
                            
                    #     elif file_state_code == "deleted":
                    #         self.__send(json.dumps({
                    #             "code": -1,
                    #             "msg": "文件已被标记为删除，请先恢复",
                    #             "data": {
                    #                 "expire_time": file_state.get("expire_time", 0)
                    #             }
                    #         }))

                    
                    handle_cursor.execute("UPDATE path_structures SET name = ? WHERE id = ?;", (new_filename, file_id))

                    self.db_conn.commit()

                    self.__send(json.dumps({
                        "code": 0,
                        "msg": "success"
                    }))

                
                elif req_action == "delete":
                    recycle_policy = Policies("recycle", self.db_conn)
                    delete_after_marked_time = recycle_policy["deleteAfterMarked"]

                    if file_state["code"] == "deleted":
                        self.__send(json.dumps({
                            "code": -1, 
                            "msg": "文件已被标记为删除"
                        }))
                        return

                    new_state = {
                        "code": "deleted",
                        "expire_time": time.time()+delete_after_marked_time
                    }

                    handle_cursor.execute("UPDATE path_structures SET state = ? WHERE id = ?;", (json.dumps(new_state), file_id))

                    self.db_conn.commit()

                    self.__send(json.dumps(self.RES_OK))

                elif req_action == "recover":

                    if file_state["code"] != "deleted":
                        self.__send(json.dumps({
                            "code": -1, 
                            "msg": "文件未被删除"
                        }))
                        return
                    
                    recovered_state = {
                        "code": "ok",
                        "expire_time": 0
                    }

                    handle_cursor.execute("UPDATE path_structures SET state = ? WHERE id = ?;", (json.dumps(recovered_state), file_id))
                    self.db_conn.commit()

                    self.__send(json.dumps(self.RES_OK))

                elif req_action == "permanently_delete":
                    self.permanentlyDeleteFile(file_id)

                    self.__send(json.dumps(self.RES_OK))

            else:
                self.__send(json.dumps({
                        "code": -1,
                        "msg": "请求的操作不存在"
                    }))
                self.log.logger.debug("请求的操作不存在。")
                return
            
            self.db_conn.commit() # 统一 commit
            handle_cursor.close()

    def handle_createUser(self, loaded_recv, user: Users):
        if "data" not in loaded_recv:
            self.__send(json.dumps(
                self.RES_MISSING_ARGUMENT
            ))
            return
        
        new_usr_username = loaded_recv["data"].get("username", None)
        new_usr_pwd = loaded_recv["data"].get("password", None)

        if not new_usr_username or not new_usr_pwd:
            self.__send(json.dumps(self.RES_MISSING_ARGUMENT))
            return
        
        if not user.hasRights(("create_user",)):
            self.__send(json.dumps(self.RES_ACCESS_DENIED))
            return
        
        new_usr_rights = loaded_recv["data"].get("rights", None)
        new_usr_groups = loaded_recv["data"].get("groups", None)

        auth_policy = Policies("user_auth", self.db_conn)

        if new_usr_groups or new_usr_rights:
            if not user.hasRights(("custom_new_user_settings")):
                self.__send(json.dumps(self.RES_ACCESS_DENIED))
                return
        
        if not new_usr_groups: # fallback
            new_usr_groups = auth_policy["default_new_user_groups"]
        if not new_usr_rights:
            new_usr_rights = auth_policy["default_new_user_rights"]

        
        handle_cursor = self.db_conn.cursor()
        
        # 随机生成8位salt
        alphabet = string.ascii_letters + string.digits
        salt = ''.join(secrets.choice(alphabet) for i in range(8)) # 安全化

        __first = hashlib.sha256(new_usr_pwd.encode()).hexdigest()
        __second_obj = hashlib.sha256()
        __second_obj.update((__first+salt).encode())

        salted_pwd = __second_obj.hexdigest()

        insert_user = (new_usr_username, salted_pwd, salt, new_usr_rights, new_usr_groups, auth_policy["default_new_user_properties"])

        handle_cursor.execute("INSERT INTO users VALUES(?, ?, ?, ?, ?, ?)", insert_user)

        self.db_conn.commit()

        self.__send(json.dumps(self.RES_OK))

        return
                


        
            

if __name__ == "__main__":
    Thread = ConnThreads(
            target=ConnHandler, name = "threadName", args=(), kwargs={}
        )
    Thread.start()
    time.sleep(1)
    print(Thread.is_alive())