# connThread.py
import threading
import time
import gettext
import sys
import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class ConnThreads(threading.Thread):
    def __init__(self, target, name, args=(), kwargs={}):
        super().__init__()
        self.target = target
        self.name = name # 只能是这个变量名
        # 传给真正的处理类
        self.args = args
        self.kwargs = kwargs

    def run(self):
        target_class = self.target(*self.args, **self.kwargs)
        target_class.thread_name = self.name
        try:
            target_class.main()
        except Exception as e:
            e.add_note("看起来线程内部的运行出现了问题。")
            raise

class ConnHandler():
    def __init__(self, *args, **kwargs): #!!注意，self.thread_name 在调用类定义！
        self.args = args
        self.kwargs = kwargs

        self.conn = kwargs["conn"]
        self.addr = kwargs["addr"]

        self.rsa_ekey, self.rsa_fkey = kwargs['rsa_keys']

        self.config = kwargs["toml_config"] # 导入配置字典

        self.locale = self.config['general']['locale']
        self.root_abspath = kwargs["root_abspath"]

        sys.path.append(f"{self.root_abspath}/include/") # 增加导入位置

        from logtool import LogClass
        self.log = LogClass(logname=f"main.connHandler.{self.thread_name}", filepath=f'{self.root_abspath}/main.log')

        self.BUFFER_SIZE = 1024

        self.encrypted_connection = False
        self.__initRSA()
        
    def __initRSA(self):
        with open(f"{self.root_abspath}/content/pri.pem", "rb") as pri_file:
            self.private_key = RSA.import_key(pri_file.read())
        self.pri_cipher = PKCS1_OAEP.new(self.private_key)

        with open(f"{self.root_abspath}/content/pub.pem", "rb") as pub_file:
            self.public_key = RSA.import_key(pub_file.read())
        self.pub_cipher = PKCS1_OAEP.new(self.public_key)


    def __send(self, msg):
        if self.encrypted_connection:
            pass
        pass

    def __recv(self, msg):
        total_data = bytes()
        while True:
            # 将收到的数据拼接起来
            data = self.conn.recv(self.BUFFER_SIZE)
            total_data += data
            if len(data) < self.BUFFER_SIZE:
                break
        return total_data

    def _doFirstCommunication(self, conn):
        receive = self.__recv()
        if receive == "hello":
            conn.send("hello")
        else:
            conn.send("Unknown request")
            return False
        
        conn.send(json.dumps({
            "msg": "enableEncryption",
            "public_key": self.public_key,
            "code": 0
        }))

        receive_encrypted = conn.recv(self.BUFFER_SIZE)

        decrypted_data = self.pri_cipher.decrypt(receive_encrypted)

        print(decrypted_data.decode())
        return True

    def main(self):
        conn = self.conn # 设置别名

        es = gettext.translation("connHandler", localedir=self.root_abspath + "/content/locale", languages=[self.locale], fallback=True)
        es.install()

        if not self._doFirstCommunication(conn):
            conn.close()
            sys.exit()

        while True:
            recv = self.conn.recv(self.BUFFER_SIZE)
            conn.send("hello")
            break

if __name__ == "__main__":
    Thread = ConnThreads(
            target=ConnHandler, name = "threadName", args=(), kwargs={}
        )
    Thread.start()
    time.sleep(1)
    print(Thread.is_alive())