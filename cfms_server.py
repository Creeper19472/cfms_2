# -*- coding:utf-8 -*-

CORE_VERSION = "1.0.0.230607_alpha"

# import importlib

import sys, os, json, socket, sqlite3, gettext, time, random, threading
import tomllib
import hashlib

import include
import include.logtool as logtool
from include.connThread import *

from Crypto.PublicKey import RSA

class DB_Sqlite3(object):
    def __init__(self, filename):
        try:
            self.conn = sqlite3.connect(filename)
        except Exception as e:
            e.add_note("在打开数据库连接时出现了问题。")
            raise
        self.cursor = self.conn.cursor()
        
    def execWithCommit(self, execute):
        self.cursor.execute(execute)
        self.conn.commit()

    def close(self):
        self.conn.close()

def dbInit(db_object):
    cur = db_object.conn.cursor()
    cur.execute("CREATE TABLE users(username TEXT, hash TEXT, salt TEXT, rights BLOB, groups BLOB)")
    """
    rights: 额外权限。接受列表输入。
    此栏包含的权限将附加于用户个人。
    groups: 用户组。
    """
    # 初始化密码
    # 获取由4位随机大小写字母、数字组成的salt值
    def create_salt(length = 4):
        salt = ''
        chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
        len_chars = len(chars) - 1
        for i in range(0, length):
            # 每次从chars中随机取一位
            salt += chars[random.randint(0, len_chars)]
        return salt

    def create_sha256(pwd, salt):
        sha256_obj = hashlib.sha256()
        sha256_obj.update((pwd + salt).encode())
        return sha256_obj.hexdigest()

    # 原始密码
    pwd = '123456'
    # 随机生成4位salt
    salt = create_salt()
    # 加密后的密码
    sha256 = create_sha256(pwd, salt)

    print('[pwd]\n',pwd)
    print('[salt]\n', salt)
    print('[sha256]\n', sha256)

    insert_users = (
        ("admin", sha256, salt, json.dumps(["root"]), json.dumps(["sysop"])),
        ("guest", sha256, salt, json.dumps([]), json.dumps([]))
    )
    cur.executemany("INSERT INTO users VALUES(?, ?, ?, ?, ?)", insert_users)

    # 新建文档索引表

    cur.execute("CREATE TABLE document_indexes(id TEXT, filename TEXT, abspath TEXT, owner TEXT, metadata BLOB)")
    # metadata = {
    # "require": ["read"],
    # "date": "YYMMDD"
    # }
    # 默认的abspath文件名为filename+id的md5
    insert_doc = ("0", "hello.txt", root_abspath+"/content/hello.txt", "admin", json.dumps({}))
    cur.execute("INSERT INTO document_indexes VALUES(?, ?, ?, ?, ?)", insert_doc)

    # 新建组定义表
    cur.execute("CREATE TABLE groups(id TEXT, name TEXT, enabled INT, rights BLOB, metadata BLOB)")
    insert_groups = (
        ("0", "sysop", 1, json.dumps([]), json.dumps({})),
        ("1", "user", 1, json.dumps(['read']), json.dumps({}))
    )
    cur.executemany("INSERT INTO groups VALUES(?, ?, ?, ?, ?)", insert_groups)

    db_object.conn.commit()

    # 生成一对长度为 2048 位的 RSA 秘钥对, 使用默认的随机数生成函数,
    # 也可以手动指定一个随机数生成函数: randfunc=Crypto.Random.new().read
    rsa_key = RSA.generate(2048)
    print(rsa_key)                      # Private RSA key at 0x7FB241173748
    print(type(rsa_key))                # <class 'Crypto.PublicKey.RSA.RsaKey'>


    # 导出公钥, "PEM" 表示使用文本编码输出, 返回的是 bytes 类型, 格式如下:
    # b'-----BEGIN PUBLIC KEY-----\n{Base64Text}\n-----END PUBLIC KEY-----'
    # 输出格式可选: "PEM", "DER", "OpenSSH"
    pub_key = rsa_key.publickey().export_key("PEM")

    # 导出私钥, "PEM" 表示使用文本编码输出, 返回的是 bytes 类型, 格式如下:
    # b'-----BEGIN RSA PRIVATE KEY-----\n{Base64Text}\n-----END RSA PRIVATE KEY-----'
    pri_key = rsa_key.export_key("PEM")


    # 转换为文本打印输出公钥和私钥
    print(pub_key.decode())
    print(pri_key.decode())


    # 把公钥和私钥保存到文件
    with open("content/pub.pem", "wb") as pub_fp:
        pub_fp.write(pub_key)

    with open("content/pri.pem", "wb") as pri_fp:
        pri_fp.write(pri_key)

def mainloop():
    created_count = 0
    while True:
        # 建立客户端连接
        conn, addr = server.accept()      

        log.logger.info("连接地址: %s" % str(addr))

        created_count += 1

        actives = threading.enumerate()
    
        thread_name = f"Thread-{created_count}"
        Thread = ConnThreads(
            target=ConnHandler, name=thread_name, args=(), kwargs={
                "conn": conn,
                "addr": addr,
                "db_conn": maindb.conn
            }
        )
        Thread.start()
        log.logger.debug(_("A new thread %s has started.") % thread_name)
        
    while True:
        threadingnum_max = 10000
        threadings,threadnum = [],None
        conn, addr = server.accept()  # 等待连接,多个连接的时候就会出现问题,其实返回了两个值
        log.logger.info(_("New connection: %s") % str(addr))
        while (threadnum in threadings or threadnum == None) and len(threadings) <=threadingnum_max:
            threadnum = random.randint(1, threadingnum_max+1)
        threadings.append(threadnum)
        if len(threadings) >threadingnum_max:
            print(f"The maximum number({threadingnum_max}) of connections is reached!")
            del(threadings[-1])
            threadnum = None
        else:        
            threadName = f"Thread-{threadnum}"
            Thread = threading.Thread(
                target=ConnHandlerObject, args=threadName, **{'root_dir':current_dir, \
                    'rsa_keys': (ekey, fkey),'config': config, 'conn': conn, 'addr': addr}
            )
            Thread.start()
            log.logger.debug(f"A new thread {threadName} has started.")
            Thread.join()
            info = threadings.pop(threadnum)
            log.logger.info(f"The user({info}) disconnected")

# 获取初始绝对路径
# 结果最后不带斜杠，需要手动添加
root_abspath = os.path.dirname(os.path.abspath(__file__))

print(root_abspath)
## 开始执行初始化过程

log = logtool.log(logname="main", filepath=''.join((root_abspath, '/main.log')))

if __name__ == "__main__":
    ### 如果被作为主程序运行，就开始面向前台的准备过程
    # load toml
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)
    log.logger.debug(config)

    starttime = time.time()
    log.logger.info("Starting Classified File Management System - Server...")
    log.logger.info(f"Version {CORE_VERSION}")
    log.logger.info("Running On: Python %s" % sys.version)
    if sys.version_info[0] < 3: # 基于Python 3.11 开发，因此低于此版本就无法运行
        log.logger.fatal("您正在运行的 Python 版本低于本系统的最低要求。")
        log.logger.fatal("由于此原因，程序无法继续。")
        sys.exit()

    maindb = DB_Sqlite3(f"{root_abspath}/general.db")

    m_cur = maindb.conn.cursor()

    # 加载语言配置
    language = config["general"]["locale"]
    es = gettext.translation("main", localedir="./include/locale", languages=["zh_CN"], fallback=True)
    es.install()

    # 检查数据库存在性，没有就初始化

    # m_cur.execute("CREATE TABLE IF NOT EXISTS movie(title, year, score)")
    
    m_cur.execute("select count(name) from sqlite_master where type='table' order by name;")
    if not m_cur.fetchone()[0]: # count 为0（False）时执行初始化
        dbInit(maindb)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

    ipv4_addr = (config["connect"]["ipv4_addr"], config["connect"]["port"])
    ipv6_addr = (config["connect"]["ipv6_addr"], config["connect"]["port"])

    if config["connect"]["ipv4_enabled"]:
        server.bind(ipv4_addr)
        server.listen(0)
    if config["connect"]["ipv6_enabled"]:
        server.bind(ipv6_addr)
        server.listen(0)
    
    if config["connect"]["ipv4_enabled"]:
        log.logger.info(_(f"IPv4 Address: {ipv4_addr}"))
    else:
        log.logger.info(_("IPv4 is not supported."))
    if config["connect"]["ipv6_enabled"]:
        log.logger.info(_(f"IPv6 Address: {ipv6_addr}"))
    else:
        log.logger.info(_("IPv6 is not supported."))
    

    try:
        mainloop()
    except KeyboardInterrupt:
        print("bye")
    finally:
        maindb.close()
        sys.exit()