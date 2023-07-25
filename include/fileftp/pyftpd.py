import multiprocessing
import platform
import threading
import time

import sys
sys.path.append("./include/") # relative hack

from modules.pyftpdlib.servers import ThreadedFTPServer  # <-

import os
import sys, json
import hashlib

import secrets, shutil
import sqlite3

from modules.pyftpdlib.log import logger

from modules.pyftpdlib.handlers import FTPHandler
from modules.pyftpdlib.handlers import TLS_FTPHandler

from modules.pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed

import logging

if os.name == "nt":
    import ctypes

    def isSystemAdmin():

        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False



class FTPCustomizedHandler(TLS_FTPHandler):
    def __init__(self, conn, server, ioloop=None):
        super().__init__(conn, server, ioloop)
        self.timeout = 120

    def handle_timeout(self):
        """Called when client does not send any command within the time
        specified in <timeout> attribute."""
        msg = "Control connection timed out."
        self.respond("421 " + msg, logfun=logger.info)
        # self.close() # right now, trying to solve cpu 20%

    def on_disconnect(self):
        """Called when connection is closed."""
        if self.authenticated:
            self.authorizer.remove_user(self.username) # cleanup

    def on_file_sent(self, file):
        """Called every time a file has been successfully sent.
        "file" is the absolute name of the file just being sent.
        """
        fq_db = sqlite3.connect(f"{ROOT_ABSPATH}/content/fqueue.db")
        fq_cursor = fq_db.cursor()

        # print(type(username))

        fq_cursor.execute("UPDATE ft_queue SET done = 1 WHERE task_id = ?;" , (self.username,))

        fq_db.commit()
        fq_db.close()

    def on_file_received(self, file):
        """Called every time a file has been successfully received.
        "file" is the absolute name of the file just being received.
        """
        fq_db = sqlite3.connect(f"{ROOT_ABSPATH}/content/fqueue.db")
        fq_cursor = fq_db.cursor()

        return_code = 0

        if self.authorizer.operation == "write":

            if os.path.exists(f"{self.authorizer.fake_abspath}/{self.authorizer.fake_file_id}"):

                try:
                    shutil.copyfile(self.authorizer.fake_abspath+"/"+self.authorizer.fake_file_id, self.authorizer.real_file_path)
                except Exception as e:
                    logging.error("在复制文件时出现问题。", exc_info=True)
                    return_code = -1
            
            else: 

                logging.debug("文件上传确已完成，但指定名称的文件并不存在.")
                return_code = -1

        fq_cursor.execute("UPDATE ft_queue SET done = ? WHERE task_id = ?;" , (return_code, self.username))

        fq_db.commit()
        fq_db.close()

    def on_login_failed(self, username, password):
        # self.close() # temp fix
        pass


class DummyMD5Authorizer(DummyAuthorizer):
    def __init__(self):
        super().__init__()

        self.fake_abspath = None
        self.operation = None

    def validate_authentication(self, username, password, handler):

        g_db = sqlite3.connect(f"{ROOT_ABSPATH}/general.db")
        g_cursor = g_db.cursor()

        fq_db = sqlite3.connect(f"{ROOT_ABSPATH}/content/fqueue.db")
        fq_cursor = fq_db.cursor()

        # print(type(username))

        fq_cursor.execute("SELECT count(task_id) from ft_queue where task_id = ?" , (username,))
        result = fq_cursor.fetchone()

        # print(username ,result)

        if not result:
            raise AuthenticationFailed

        if result[0] != 1:
            raise AuthenticationFailed

        fq_cursor.execute("SELECT token from ft_queue where task_id = ?", (username,))

        hash, salt = json.loads(fq_cursor.fetchone()[0])

        sha256_obj = hashlib.sha256()
        sha256_obj.update((password+salt).encode())

        # print(sha256_obj.hexdigest())

        try:
            if not secrets.compare_digest(hash, sha256_obj.hexdigest()): # hash != sha256_obj.hexdigest():
                raise KeyError
        except KeyError:
            raise AuthenticationFailed
        
        fq_cursor.execute("SELECT done, expire_time, operation from ft_queue where task_id = ?", (username,))

        if_done, expire_time, operation = fq_cursor.fetchone()

        if if_done != 0: # 可能存在的情况：0 - 未完成，1 - 已完成，-1 - 出现错误，-2 - 任务被取消 
            raise AuthenticationFailed # if a task is done, this account will not be able to access again
        
        if expire_time and (expire_time < time.time()): # 任务过期？
            raise AuthenticationFailed

        if not self.has_user(username): 
            # 如果无该用户则初始化，但未断开前不会清除临时用户，故对用户权限的更改在下次连接才能生效
            if operation == "write":
                self.add_user(username, hash, perm='elrawT',operation="write")
            elif operation == "read":
                self.add_user(username, hash, operation="read")
            else:
                raise ValueError("Unsupported operation type")
            
            

    def add_user(self, username, password, perm='elr', msg_login="Login successful.", msg_quit="Goodbye.", operation="read"):
        if self.has_user(username):
            raise ValueError('user %r already exists' % username)
        
        # print("add_user triggered")
        
        ### 初始化用户文件夹
        g_db = sqlite3.connect(f"{ROOT_ABSPATH}/general.db")
        g_cursor = g_db.cursor()

        fq_db = sqlite3.connect(f"{ROOT_ABSPATH}/content/fqueue.db")
        fq_cursor = fq_db.cursor()

        # return self.user_table[username]['home']

        # 获取仍未完成的任务(未检查是否逾期，因这一步骤在登录时完成)，减少IO开销
        fq_cursor.execute("SELECT file_id, fake_id, fake_dir FROM ft_queue WHERE task_id = ? AND done = 0;", (username,))

        query_results = fq_cursor.fetchall()

        # 取第一条结果的内容作为一致性值的结果，忽略之后的不同情况
        fake_dir = query_results[0][2]

        if not fake_dir:
            fake_dir = username # secrets.token_hex(64)

        fake_abspath = f"{ROOT_ABSPATH}/content/temp/{fake_dir}"

        if not os.path.exists(fake_abspath):
            # print("not exists")
            os.makedirs(fake_abspath)

        # 遍历文件列表，执行复制（链接）操作
        for i in query_results:
            file_id, fake_id = i[0,1]

            # 查询
            g_cursor.execute("SELECT abspath FROM document_indexes WHERE id = ?", (file_id,))
            real_file_path = g_cursor.fetchone()[0]

            if real_file_path:

                if operation == "read":
                    # print("read mode detected")
                    real_file_abspath = os.path.abspath(real_file_path)
                    # print(real_file_abspath)

                    if not os.path.isfile(f"{fake_abspath}/{fake_id}"): # slow

                        if os.name == "nt" and tuple(map(int, platform.version().split("."))) >= (10, 0): # 试图优化 IO 开销

                            if isSystemAdmin():
                                # print("Admin")
                                os.system(f'mklink /H "{fake_abspath}/{fake_id}" {real_file_abspath}')
                            else:
                                # print("Copying file")
                                shutil.copyfile(real_file_abspath, f"{fake_abspath}/{fake_id}")

                        elif os.name == "posix":
                            try:
                                os.system(f"ln {real_file_abspath} {fake_abspath}/{fake_id} -s ")
                            except OSError:
                                shutil.copyfile(real_file_abspath, f"{fake_abspath}/{fake_id}")

                        else:
                            # print("else copyfile")
                            shutil.copyfile(real_file_abspath, f"{fake_abspath}/{fake_id}")

            else:
                raise sqlite3.DatabaseError("document_indexes 应当记录文件的绝对路径，但它为空")
        
        ### 初始化部分结束

        self._check_permissions(username, perm)
        dic = {'pwd': str(password), # actually unused
            'perm': perm,
            'operms': {},
            'msg_login': str(msg_login),
            'msg_quit': str(msg_quit),
            'home': fake_abspath,
            'operation': operation
            }
        self.user_table[username] = dic

    def get_home_dir(self, username):
        return self.user_table[username]['home']
    
    def remove_user(self, username):
        """Remove a user from the virtual users table."""

        # 清除临时文件夹
        os.removedirs(self.user_table[username]["home"])

        del self.user_table[username]



def main(root_abspath, shutdown_event: threading.Event, addr: tuple):
    global ROOT_ABSPATH
    ROOT_ABSPATH = root_abspath

    # sys.path.append(f"{ROOT_ABSPATH}/include/") # 增加导入位置

    authorizer = DummyMD5Authorizer()
    # authorizer.add_user('user', '12345', '.')
    handler = FTPCustomizedHandler

    handler.certfile = f'{ROOT_ABSPATH}/content/auth/ftp_client.crt'
    handler.keyfile = f'{ROOT_ABSPATH}/content/auth/ftp_client.key'

    # requires SSL for both control and data channel
    handler.tls_control_required = True
    handler.tls_data_required = True

    handler.authorizer = authorizer
    server = ThreadedFTPServer(addr, handler)

    lfhandler = logging.FileHandler(filename=f"{ROOT_ABSPATH}/content/logs/pyftpd.log")
    cshandler = logging.StreamHandler()
    formatter1 = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    formatter2 = logging.Formatter("[%(asctime)s %(levelname)s] %(message)s")
    lfhandler.setLevel(logging.DEBUG)
    # lfhandler.setLevel(logging.INFO)
    cshandler.setLevel(logging.INFO)
    lfhandler.setFormatter(formatter1)
    cshandler.setFormatter(formatter2)

    logging.basicConfig(handlers=(lfhandler, cshandler), level=logging.DEBUG)

    while not shutdown_event.is_set():
        server.serve_forever(blocking=False)

    logging.info(
        ">>> shutting down FTP server (%s active workers) <<<",
        server._map_len())
    
    server.close_all()
    sys.exit()

if __name__ == "__main__":
    main("B:\crp9472_personal\cfms_2", shutdown_event=threading.Event()) #TODO