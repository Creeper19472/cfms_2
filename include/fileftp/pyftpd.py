import multiprocessing

from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import ThreadedFTPServer  # <-

import os
import sys, json
import hashlib

import secrets, shutil
import sqlite3

from pyftpdlib.handlers import FTPHandler
from pyftpdlib.handlers import TLS_FTPHandler

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed

import logging

class FTPCustomizedHandler(TLS_FTPHandler):
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

        # print(type(username))

        fq_cursor.execute("UPDATE ft_queue SET done = 1 WHERE task_id = ?;" , (self.username,))

        fq_db.commit()
        fq_db.close()


class DummyMD5Authorizer(DummyAuthorizer):
    def __init__(self):
        super().__init__()

        self.fake_abspath = None

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
            if hash != sha256_obj.hexdigest():
                raise KeyError
        except KeyError:
            raise AuthenticationFailed
        
        fq_cursor.execute("SELECT done, operation from ft_queue where task_id = ?", (username,))

        if_done, operation = fq_cursor.fetchone()

        if if_done:
            raise AuthenticationFailed # if a task is done, this account will not be able to access again

        if not self.has_user(username): 
            # 如果无该用户则初始化，但未断开前不会清除临时用户，故对用户权限的更改在下次连接才能生效
            if operation == "write":
                self.add_user(username, hash, perm='elrawT')
            elif operation == "read":
                self.add_user(username, hash)
            else:
                raise ValueError("Unsupported operation type")

    def add_user(self, username, password, perm='elr', msg_login="Login successful.", msg_quit="Goodbye."):
        if self.has_user(username):
            raise ValueError('user %r already exists' % username)

        self._check_permissions(username, perm)
        dic = {'pwd': str(password), # actually unused
            'perm': perm,
            'operms': {},
            'msg_login': str(msg_login),
            'msg_quit': str(msg_quit)
            }
        self.user_table[username] = dic

    def get_home_dir(self, username):
        g_db = sqlite3.connect(f"{ROOT_ABSPATH}/general.db")
        g_cursor = g_db.cursor()

        fq_db = sqlite3.connect(f"{ROOT_ABSPATH}/content/fqueue.db")
        fq_cursor = fq_db.cursor()

        if self.fake_abspath:
            return self.fake_abspath
        # return self.user_table[username]['home']
        fq_cursor.execute("SELECT file_id, fake_id, fake_dir FROM ft_queue WHERE task_id = ? ", (username,))

        file_id, fake_id, fake_dir = fq_cursor.fetchone()

        if not fake_dir:
            fake_dir = username # secrets.token_hex(64)

        self.fake_abspath = f"{ROOT_ABSPATH}/content/temp/{fake_dir}"
        self.user_table[username]['home'] = self.fake_abspath

        if not os.path.exists(self.fake_abspath):
            os.makedirs(self.fake_abspath)
        
        # copy files
        g_cursor.execute("SELECT abspath FROM document_indexes WHERE id = ?", (file_id,))
        real_file_path = g_cursor.fetchone()[0]

        if real_file_path:

            if not os.path.isfile(f"{self.fake_abspath}/{fake_id}"): # slow
                shutil.copyfile(real_file_path, f"{self.fake_abspath}/{fake_id}")

        return self.fake_abspath



def main(root_abspath, port=5104):
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
    server = ThreadedFTPServer(('', port), handler)

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

    server.serve_forever()

if __name__ == "__main__":
    main("B:\crp9472_personal\cfms_2") #TODO