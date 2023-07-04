# -*- coding:utf-8 -*-

CORE_VERSION = "1.0.0.230628_alpha"

# import importlib

import logging
import sys, os, json, socket, sqlite3, gettext, time, random, threading
import tomllib
import hashlib
import socketserver # 准备切到 socketserver
import include
import include.logtool as logtool
from include.connThread import * 
from Crypto.PublicKey import RSA

import include.filesrv.ftserver as ftserver

import secrets

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
        first = hashlib.sha256(pwd.encode()).hexdigest()
        second_obj = hashlib.sha256()
        second_obj.update((first+salt).encode())
        return second_obj.hexdigest()

    # 原始密码
    pwd = '123456'
    # 随机生成4位salt
    salt = create_salt()
    # 加密后的密码
    sha256 = create_sha256(pwd, salt)

    print('[pwd]\n',pwd)
    print('[salt]\n', salt)
    print('[sha256]\n', sha256)

    user_rights = {
        "root": {
            "expire": 0
        }
    }

    user_groups = {
        "sysop": {
            "expire": 0
        }
    }

    insert_users = (
        ("admin", sha256, salt, json.dumps(user_rights), json.dumps(user_groups)),
        ("guest", sha256, salt, json.dumps({}), json.dumps({}))
    )
    cur.executemany("INSERT INTO users VALUES(?, ?, ?, ?, ?)", insert_users)

    # 新建文档索引表
    
    # now document_indexes does not store external data
    cur.execute("CREATE TABLE document_indexes(id TEXT, abspath TEXT)") 
    
    # metadata = {
    # "require": ["read"],
    # "date": "YYMMDD"
    # }
    # 默认的abspath文件名为filename+id的md5

    insert_doc = ("0", root_abspath+"/content/hello.txt") # 潜在问题：不能整体打包移动
    cur.execute("INSERT INTO document_indexes VALUES(?, ?)", insert_doc)

    # 新建组定义表
    cur.execute("CREATE TABLE groups(id TEXT, name TEXT, enabled INT, rights BLOB, properties BLOB)")

    group_rights = {
        "read": {
            "expire": 0
        }
    }

    insert_groups = (
        ("0", "sysop", 1, json.dumps(group_rights), json.dumps({})),
        ("1", "user", 1, json.dumps(group_rights), json.dumps({}))
    )
    cur.executemany("INSERT INTO groups VALUES(?, ?, ?, ?, ?)", insert_groups)

    # 新建伪路径索引定义表
    cur.execute("CREATE TABLE path_structures(id TEXT, name TEXT, parent_id TEXT, type TEXT, file_id TEXT, access_rules BLOB, external_access BLOB, properties BLOB)")
    # file_id: 如果是文件就必须有；文件夹应该没有

    insert_doc_access_rules = {
        "read": [],
        "write": []
    }
    

    insert_doc_external_access = { # 这里的 access 下记录的是允许的操作而非权限，即：read, write, delete, permanently_delete, rename
        "groups": {
            "sysop": {
                "read": {
                    "expire": 0
                },
                "permanently_delete": {
                    "expire": 0
                }
            }
        },
        "users": {}
    }


    insert_paths = (
        ("C00001", "hello.txt", "", "file", "0", json.dumps(insert_doc_access_rules), json.dumps(insert_doc_external_access), json.dumps({})),
    )
    cur.executemany("INSERT INTO path_structures VALUES(?, ?, ?, ?, ?, ?, ?, ?)", insert_paths)

    # create config table(internal)
    cur.execute("CREATE TABLE cfms_internal(id TEXT, key TEXT, value BLOB)")
    cur.execute("INSERT INTO cfms_internal VALUES(?, ?, ?)", (0, "db_version", CORE_VERSION))


    db_object.conn.commit()

    # 生成一对长度为 2048 位的 RSA 秘钥对, 使用默认的随机数生成函数,
    # 也可以手动指定一个随机数生成函数: randfunc=Crypto.Random.new().read
    rsa_key = RSA.generate(4096)
    # print(rsa_key)                      # Private RSA key at 0x7FB241173748
    # print(type(rsa_key))                # <class 'Crypto.PublicKey.RSA.RsaKey'>


    # 导出公钥, "PEM" 表示使用文本编码输出, 返回的是 bytes 类型, 格式如下:
    # b'-----BEGIN PUBLIC KEY-----\n{Base64Text}\n-----END PUBLIC KEY-----'
    # 输出格式可选: "PEM", "DER", "OpenSSH"
    pub_key = rsa_key.publickey().export_key("PEM")

    # 导出私钥, "PEM" 表示使用文本编码输出, 返回的是 bytes 类型, 格式如下:
    # b'-----BEGIN RSA PRIVATE KEY-----\n{Base64Text}\n-----END RSA PRIVATE KEY-----'
    pri_key = rsa_key.export_key("PEM")


    # 转换为文本打印输出公钥和私钥
    # print(pub_key.decode())
    # print(pri_key.decode())


    # 把公钥和私钥保存到文件
    with open("content/auth/pub.pem", "wb") as pub_fp:
        pub_fp.write(pub_key)

    with open("content/auth/pri.pem", "wb") as pri_fp:
        pri_fp.write(pri_key)

    ### 新建文件传输临时列表数据库

    with open("content/fqueue.db", "a") as fqueue_file:
        fqueue_file.truncate(0) # 清空

    fQueue_db = sqlite3.connect(root_abspath+"/content/fqueue.db")

    fQ_cur = fQueue_db.cursor()

    # create file transport queue table
    fQ_cur.execute("CREATE TABLE ft_queue(task_id TEXT, filename TEXT, destination TEXT)")

    fQueue_db.close()

sock_condition = True

def mainloop(serverd):
    created_count = 0

    while sock_condition:
        # 建立客户端连接

        created_count += 1

        actives = threading.enumerate()

        thread_name = f"Thread-{created_count}"

        conn, addr = serverd.accept()
        keepalive = (1,60*1000,60*1000)
        conn.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE, True) # 开启TCP保活
        conn.ioctl(socket.SIO_KEEPALIVE_VALS,keepalive)      
        
        log.logger.info(f"connection address: {addr!s}")
        
        Thread = ConnThreads(
            target=ConnHandler, name=thread_name, args=(), kwargs={
                "conn": conn,
                "addr": addr,
                "db_conn": maindb.conn,
                "toml_config": config,
                "root_abspath": root_abspath
            }
        )
        Thread.daemon = True
        Thread.start()


def stopsocket():
    # socket终止
    globals()['sock_condition'] = False
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host, port= 'localhost',config["connect"]["port"]
    clientsocket.connect((host,port))
    clientsocket.close()
    sys.exit()


def consoled():
    '''控制台
    若要添加控制台指令,在字典command_dict中添加即可'''
    log.logger.info("Command example: [command]; ")
    while True:
        try:
            i = input(">")
        except (EOFError,UnboundLocalError):pass
        if i.endswith(";"):
            command_dict = {"exit;":stopsocket,}
            command_dict[str(i)]()
                
            

# 获取初始绝对路径
# 结果最后不带斜杠，需要手动添加
root_abspath = os.path.dirname(os.path.abspath(__file__))

print(root_abspath)
## 开始执行初始化过程

log = logtool.LogClass(logname="main", filepath=''.join((root_abspath, '/main.log')))

if __name__ == "__main__":
    # 如果被作为主程序运行，就开始面向前台的准备过程

    # load toml
    try:
        with open("config.toml", "rb") as f:
            config = tomllib.load(f)
    except FileNotFoundError as error:
        log.logger.fatal(f"{error}")
        log.logger.fatal("Terminating program running!")
        sys.exit()

    if config["debug"]["debug"]:
        log.cshandler.setLevel(logging.DEBUG)
        log.logger.info("Debug mode enabled.")
    log.logger.debug(config)

    starttime = time.time() # 这里还有个endtime，但我懒得写了

    log.logger.info("Starting Classified File Management System - Server...")
    # log.logger.info(f"Server time:{starttime}")    
    log.logger.info(f"Version {CORE_VERSION}")
    log.logger.info("Running On: Python %s" % sys.version)
    if sys.version_info[0] < 3: # 基于Python 3.11 开发，因此低于此版本就无法运行
        log.logger.fatal("您正在运行的 Python 版本低于本系统的最低要求。")
        log.logger.fatal("由于此原因，程序无法继续。")
        sys.exit()

    maindb = DB_Sqlite3(f"{root_abspath}/general.db")
    m_cur = maindb.conn.cursor()

    print(type(maindb.conn))

    # 加载语言配置
    language = config["general"]["locale"]
    es = gettext.translation("main", localedir="./include/locale", languages=[language], fallback=True)
    es.install()

    # 检查数据库存在性，没有就初始化

    # m_cur.execute("CREATE TABLE IF NOT EXISTS movie(title, year, score)")
    
    m_cur.execute("select count(name) from sqlite_master where type='table' order by name;")
    if not m_cur.fetchone()[0]: # count 为0（False）时执行初始化
        dbInit(maindb)

    # 初始化 token_secret
    if config["security"]["update_token_secret_at_startup"]:
        with open(f"{root_abspath}/content/auth/token_secret", "+a") as ts_file: # 这个文件的重要性和 pri.pem 是一样的
            ts_file.truncate(0) # 清空
            ts_file.write(secrets.token_hex(128))
            

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
        log.logger.info((f"IPv4 Address: {ipv4_addr}"))
    else:
        log.logger.info(("IPv4 is not supported."))
    if config["connect"]["ipv6_enabled"]:
        log.logger.info((f"IPv6 Address: {ipv6_addr}"))
    else:
        log.logger.info(("IPv6 is not supported."))

    mainloopThread = threading.Thread(target=lambda:mainloop(server),name="mainloop")
    mainloopThread.start()
    consoledThread = threading.Thread(target=consoled,name="consoled")
    consoledThread.start()

    # 初始化 FileServer
    fileServerThread = threading.Thread(target=ftserver.__main__, \
                                        args=(ipv4_addr[0], config["connect"]["file_cmd_port"], config["connect"]["file_data_port"], root_abspath,),\
                                        name="fileServerThread")
    fileServerThread.daemon = False
    fileServerThread.start()


