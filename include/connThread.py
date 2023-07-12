# connThread.py

import secrets
import hashlib
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
from include.bulitin_class.policies import Policies

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
            target_class.conn.close()
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

            # 判断 API 版本
            if loaded_recv.get("version", None) == 1:
                self.handle_v1(loaded_recv)
            else: # 目前仅支持 V1
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "unsupported API version or not given"
                }))
                continue

    def _verifyAccess(self, user: Users, action, access_rules: dict, external_access: dict):
        if not access_rules: # fix #7
            return True # fallback

        # access_rules 包括所有规则
        if user.ifMatchRules(access_rules[action]):
            return True
        
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

    def verifyUserAccess(self, id, action, user: Users):
        """
        用户鉴权函数。
        用于逐级检查用户是否拥有访问权限，若发生任意无情况即返回 False
        """
        self.log.logger.debug(f"verifyUserAccess(): 正在对 用户 {user.username} 访问 id: {id} 的请求 进行鉴权")

        db_cur = self.db_conn.cursor()
        db_cur.execute("SELECT parent_id, access_rules, external_access FROM path_structures WHERE id = ?", (id,))

        result = db_cur.fetchall()

        assert len(result) == 1

        por_policy = Policies("permission_on_rootdir", self.db_conn)

        if (parent:=result[0][0]):
            self.log.logger.debug(f"正在检查其父目录 {parent} 的权限...")
            if not self.verifyUserAccess(parent, action, user):
                return False
            self.log.logger.debug("完毕，无事发生。")
        elif por_policy["inherit_by_subdirectory"]:
            self.log.logger.debug("PoR_IbS 已激活，正在检查用户对于根目录的权限...")

            por_access_rules = por_policy["rules"]["access_rules"]
            por_external_access = por_policy["rules"]["external_access"]

            if not self._verifyAccess(user, action, por_access_rules, por_external_access):
                self.log.logger.debug("PoR 鉴权失败")
                return False
            else:
                self.log.logger.debug("PoR 鉴权成功")
            
        access_rules = json.loads(result[0][1])
        external_access = json.loads(result[0][2])

        self.log.logger.debug(f"所有访问规则和附加权限记录：{access_rules}, {external_access}")

        if self._verifyAccess(user, action, access_rules, external_access):
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
        
        elif loaded_recv["request"] == "getDocument":

            self.log.logger.debug("客户端请求调取文档")

            self.handle_getDocument(loaded_recv, attached_username, attached_token)

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
                "document_id": "..."
                }
        }
        """
        try:
            requested_document_id = recv["data"]["document_id"]
            other_needed_data = recv["data"].get("other_data", dict())
        except KeyError:
            self.__send(json.dumps({
                "code": -1,
                "msg": "bad request"
            }))
            return

        
        doc = Documents(requested_document_id, self.db_conn)
        doc.load()

        user = Users(req_username, self.db_conn)
        if not user.ifExists(): # 其实不必验证，但服务端签发时就要小心
            self.__send(json.dumps({
                "code": -1,
                "msg": "user does not exist"
            }))
            return
        
        user.load()


        if doc.if_exists:
            if doc.hasUserMetRequirements(user):
                self.__send(json.dumps({
                    "code": 0,
                    "msg": "developing"
                }))

    def handle_getDir(self, recv, user: object):
        path_id = recv["data"].get("id")

        if not path_id:
            self.__send(json.dumps({
                "code": -1,
                "msg": "no path_id provided"
            }))

        handle_cursor = self.db_conn.cursor()

        handle_cursor.execute("SELECT type, access_rules FROM path_structures WHERE id = ?" , (path_id,))

        result = handle_cursor.fetchone()

        if result:
            tg_type = result[0]
            access_rules = json.loads(result[1])
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
            

            handle_cursor.execute("SELECT id, name, type FROM path_structures WHERE parent_id = ?" , (path_id,))
            all_result = handle_cursor.fetchall()

            dir_result = dict()

            for i in all_result:

                if not self.verifyUserAccess(i[0], "read", user): # 检查该目录下的文件是否有权访问，如无则隐藏
                    if self.config["security"]["hide_when_no_access"]:
                        continue
                    else:
                        pass
                # print(i)
                dir_result[i[0]] = {
                    "name": i[1],
                    "type": i[2]
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

        if not self.verifyUserAccess_onPolicy(action, access_rules, external_access, user):
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

    def verifyUserAccess_onPolicy(self, action, access_rules, external_access, user: Users): # 粗暴判断，只是为了调用方便
        self.log.logger.debug(f"所有访问规则和附加权限记录：{access_rules}, {external_access}")

        if not access_rules: # TODO #7 相同逻辑更新到 verifyUserAccess()
            return True # fallback

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
                
        self.log.logger.debug("校验失败。")
        return False


        
        


        

    def handle_operateFile(self, loaded_recv, user: Users):
        file_id = loaded_recv["data"]["file_id"]

        handle_cursor = self.db_conn.cursor()

        handle_cursor.execute("SELECT name, parent_id, type, file_id, access_rules, external_access, properties FROM path_structures WHERE id = ?", \
                              (file_id,))
        
        result = handle_cursor.fetchall()

        if len(result) > 1:
            raise ValueError("Invaild query result length")
        elif len(result) < 1:
            self.__send(json.dumps({
                    "code": -1,
                    "msg": "no such file"
                }))
            return
        else:
            if result[0][2] != "file":
                self.__send(json.dumps({
                    "code": -1,
                    "msg": "not a file"
                }))
                return
            
            req_action = loaded_recv["data"]["action"]

            self.log.logger.debug(f"请求对文件的操作：{req_action}")

            if req_action in ["read", "write", "rename", "delete", "permanently_delete", "recover"]:

                if not self.verifyUserAccess(file_id, req_action, user):
                    self.__send(json.dumps({
                        "code": 403,
                        "msg": "permission denied"
                    }))
                    self.log.logger.debug("权限校验失败：无权执行所请求的操作")
                    return
                
                query_file_id = result[0][3]
                
                if req_action == "read":
                    # 权限检查已在上一步完成

                    fqueue_db = sqlite3.connect(f"{self.root_abspath}/content/fqueue.db")

                    fq_cur = fqueue_db.cursor()

                    task_id = secrets.token_hex(64)
                    
                    token_hash = secrets.token_hex(64)
                    token_salt = secrets.token_hex(16)

                    operation = "read"

                    token_hash_sha256 = hashlib.sha256(token_hash.encode()).hexdigest()
                    final_token_hash_obj = hashlib.sha256()
                    final_token_hash_obj.update((token_hash_sha256+token_salt).encode())

                    final_token_hash = final_token_hash_obj.hexdigest()

                    token_to_store = (final_token_hash, token_salt)

                    # fake_id, fake_dir(set to task_id)
                    fake_id = secrets.token_hex(64)
                    fake_dir = task_id

                    expire_time = time.time() + 3600 # TODO

                    fq_cur.execute("INSERT INTO ft_queue (task_id, operation, token, fake_id, fake_dir, file_id, expire_time, done) \
                                   VALUES ( ?, ?, ?, ?, ?, ?, ?, 0 );", (task_id, operation, json.dumps(token_to_store),\
                                                                       fake_id, fake_dir, query_file_id, expire_time))
                    
                    fqueue_db.commit()
                    fqueue_db.close()

                    response = {
                        "code": 0,
                        "msg": "ok",
                        "data": {
                            "task_id": task_id,
                            "token": token_hash_sha256, # original hash after sha256
                            "expire_time": expire_time,
                            "t_filename": fake_id
                        }
                    }

                    self.__send(json.dumps(response))

                    return
                
                elif req_action == "rename":

                    try:
                        new_filename = loaded_recv["data"]["new_filename"]
                    except ValueError:
                        self.__send(json.dumps({
                            "code": -1,
                            "msg": "not all arguments provided"
                        }))
                        return
                    
                    handle_cursor.execute("UPDATE path_structures SET name = ? WHERE id = ?;", (new_filename, query_file_id))

                    self.__send(json.dumps({
                        "code": 0,
                        "msg": "success"
                    }))

                    return
                
                elif req_action == "delete":
                    pass


            else:
                self.__send(json.dumps({
                        "code": -1,
                        "msg": "请求的操作不存在"
                    }))
                self.log.logger.debug("请求的操作不存在。")
                return
                


        
            

if __name__ == "__main__":
    Thread = ConnThreads(
            target=ConnHandler, name = "threadName", args=(), kwargs={}
        )
    Thread.start()
    time.sleep(1)
    print(Thread.is_alive())