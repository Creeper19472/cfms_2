# -*- coding:utf-8 -*-

CORE_VERSION = (1, 0, 0, "240107_alpha")
READABLE_VERSION = (
    f"{CORE_VERSION[0]}.{CORE_VERSION[1]}.{CORE_VERSION[2]}.{CORE_VERSION[3]}"
)


# import importlib

import logging
import sys, os, json, socket, sqlite3, gettext, time, random, threading
import tomllib
import hashlib
import socketserver  # 准备切到 socketserver
import include.logtool as logtool
from include.connThread import *
from Crypto.PublicKey import RSA

import include.fileftp.pyftpd as pyftpd
import include.taskScheduler as taskScheduler

import secrets
import string

# from apscheduler.schedulers.background import BackgroundScheduler
from include.database.abstracted import getDBConnection, AbstractedConnection

from include.database.pool import getDBPool

from dbutils.steady_db import SteadyDBCursor
import pluggy


# 开发模式开关
DEBUG = False


# 初始化 terminate_event
terminate_event = threading.Event()

SYS_IOLOCK = threading.RLock()

SYS_LOCKS = {"SYS_IOLOCK": SYS_IOLOCK}


def dbInit(db_object: AbstractedConnection):
    cur = db_object.cursor()
    cur.execute(
        "CREATE TABLE users (`username` VARCHAR(255) PRIMARY KEY, `hash` TEXT, `salt` TEXT, \
            `nickname` TEXT, `rights` TEXT, `groups` TEXT, `properties` TEXT, `publickey` TEXT);"
    )
    """
    rights: 额外权限。接受列表输入。
    此栏包含的权限将附加于用户个人。
    groups: 用户组。
    """

    def create_sha256(pwd, salt):
        first = hashlib.sha256(pwd.encode()).hexdigest()
        second_obj = hashlib.sha256()
        second_obj.update((first + salt).encode())
        return second_obj.hexdigest()

    # 原始密码
    if not DEBUG:
        # admin_username = secrets.token_hex(8)
        pwd = secrets.token_hex(8)  # 改用随机生成
    else:
        pwd = "123456"

    # 随机生成8位salt
    alphabet = string.ascii_letters + string.digits
    salt = "".join(secrets.choice(alphabet) for i in range(8))  # 安全化
    # 加密后的密码
    sha256 = create_sha256(pwd, salt)

    print("[pwd]\n", pwd)
    print("[salt]\n", salt)
    print("[sha256]\n", sha256)

    user_rights = {"root": {"expire": 0}}

    user_groups = {"sysop": {"expire": 0}}

    user_properties = {
        "state": 0,
        "state_description": {"time": 0, "operator": None, "reason": None},
        "nickname": None,
        "avatar": {"file_id": None},
        "publicity": {
            "restricted": True,
            "access_rules": {"read": []},
            # 是一个元组，但只适用于 read 操作；他人修改另有权限判断；
            "external_access": {},
        },
    }

    insert_users = (
        (
            "admin",
            sha256,
            salt,
            "Administrator",
            json.dumps(user_rights),
            json.dumps(user_groups),
            json.dumps(user_properties),
            None,
        ),
        (
            "guest",
            sha256,
            salt,
            "Guest",
            json.dumps({}),
            json.dumps({}),
            json.dumps(user_properties),
            None,
        ),
    )
    cur.executemany(
        "INSERT INTO users (`username`, `hash`, `salt`, `nickname`, `rights`, `groups`, `properties`, `publickey`) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
        insert_users,
    )

    # 新建文档索引表

    # now document_indexes does not store external data
    cur.execute(
        "CREATE TABLE document_indexes(`id` VARCHAR(255) PRIMARY KEY, `abspath` TEXT)"
    )

    # metadata = {
    # "require": ["read"],
    # "date": "YYMMDD"
    # }
    # 默认的abspath文件名为filename+id的md5

    insert_doc = (
        ("0", root_abspath + "/content/hello.txt"),  # 潜在问题：不能整体打包移动
        ("DEFAULT_USER_AVATAR", root_abspath + "/content/files/user.png"),
    )
    cur.executemany("INSERT INTO document_indexes VALUES(?, ?)", insert_doc)

    # 新建组定义表

    if isinstance(cur, (sqlite3.Cursor, SteadyDBCursor)):
        cur.execute(
            "CREATE TABLE `groups` (`id` INTEGER PRIMARY KEY, `name` TEXT, `enabled` INT, `rights` BLOB, `properties` BLOB)"
        )
    else:
        cur.execute(
            "CREATE TABLE `groups` (`id` INT(4) PRIMARY KEY AUTO_INCREMENT, `name` TEXT, `enabled` INT, `rights` BLOB, `properties` BLOB)"
        )

    sysop_group_rights = {
        "super_useravatar": {"expire": 0},
        "super_access": {"expire": 0},
        "view_deleted": {"expire": 0},
        "permanently_delete": {"expire": 0},
        "shutdown": {"expire": 0},
        "create_user": {},
        "create_dir": {},
        "custom_new_user_settings": {},
        "create_group": {},
        "custom_new_group_settings": {},
        "custom_new_group_members": {},
        "view_others_properties": {},
        "change_id": {},
        "edit_other_users": {},
        "set_usergroups": {},
        "set_userrights": {},
    }

    user_group_rights = {"set_nickname": {}, "read": {"expire": 0}}

    insert_groups = (
        ("sysop", 1, json.dumps(sysop_group_rights), json.dumps({})),
        ("user", 1, json.dumps(user_group_rights), json.dumps({})),
    )
    cur.executemany(
        "INSERT INTO `groups` (`name`, `enabled`, `rights`, `properties`) VALUES(?, ?, ?, ?)",
        insert_groups,
    )

    # 新建伪路径索引定义表
    cur.execute(
        "CREATE TABLE path_structures\
                (`id` VARCHAR(255) PRIMARY KEY, `name` TEXT, `owner` TEXT, `parent_id` TEXT, `type` TEXT, \
                `revisions` TEXT, `access_rules` BLOB, `external_access` BLOB, `properties` BLOB, `state` TEXT)"
    )
    # file_id: 如果是文件就必须有；文件夹应该没有

    insert_doc_access_rules = {
        "__noinherit__": [],  # 仅当上层启用继承时才有效；deny 设置有特殊格式，deny_ 开头后接 action 表示单独操作的 deny 规则不继承
        "read": [],
        "write": [],
        "deny": {
            "read": {
                "groups": {
                    # "sysop": {
                    #     "expire": 0
                    # }
                },
                "users": {},
                "rules": [],
            },
            "write": {},
        },
    }

    insert_dir_access_rules = {
        "__noinherit__": [],  # 仅当上层启用继承时才有效；deny 设置则将导致所有 deny 规则不继承
        "__subinherit__": True,  # 是否被下层所继承，如果为 False，则在判断时将返回为真；仅目录有此设置
        "read": [],
        "write": [],
        "deny": {"read": [], "write": []},
    }

    insert_doc_external_access = (
        {  # 这里的 access 下记录的是允许的操作而非权限，即：read, write, delete, permanently_delete, rename
            "groups": {
                "sysop": {"read": {"expire": 0}, "permanently_delete": {"expire": 0}}
            },
            "users": {},
        }
    )

    insert_doc_state = {"code": "ok", "expire_time": 0}

    import uuid

    insert_doc_revisions = {
        uuid.uuid4().hex: {
            "file_id": "0",
            "state": {"code": "ok", "expire_time": 0},
            "access_rules": {},
            "external_access": {},
            "time": time.time(),
        }
    }

    insert_paths = (
        (
            "C00001",
            "hello.txt",
            json.dumps((("user", "admin"),)),
            "dir01",
            "file",
            json.dumps(insert_doc_revisions),
            json.dumps(insert_doc_access_rules),
            json.dumps(insert_doc_external_access),
            json.dumps({}),
            json.dumps(insert_doc_state),
        ),
        (
            "dir01",
            "Test Dir",
            json.dumps((("user", "admin"),)),
            "",
            "dir",
            None,
            json.dumps(insert_dir_access_rules),
            json.dumps(insert_doc_external_access),
            json.dumps({}),
            json.dumps(insert_doc_state),
        ),
    )
    cur.executemany(
        "INSERT INTO path_structures VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", insert_paths
    )

    # create config table(internal)
    if isinstance(cur, (sqlite3.Cursor, SteadyDBCursor)):
        cur.execute(
            "CREATE TABLE cfms_internal(`id` INTEGER PRIMARY KEY, `key` TEXT, `value` BLOB)"
        )
    else:
        cur.execute(
            "CREATE TABLE cfms_internal(`id` INT(4) PRIMARY KEY AUTO_INCREMENT, `key` TEXT, `value` BLOB)"
        )

    cur.execute(
        "INSERT INTO cfms_internal (`key`, `value`) VALUES(?, ?)",
        ("db_version", READABLE_VERSION),
    )

    # create policy table
    log.logger.debug("正在创建策略表。")
    cur.execute(
        "CREATE TABLE `policies`(`id` VARCHAR(255) PRIMARY KEY, `content` TEXT, `access_rules` TEXT, `external_access` TEXT)"
    )

    for dirpath, dirnames, filenames in os.walk(
        f"{root_abspath}/include/initial_policies"
    ):
        for file in filenames:
            if not file.endswith(".json"):
                continue
            with open(
                os.path.join(dirpath, file), "r", encoding="utf-8"
            ) as f:  # force utf-8
                loaded_json = json.load(f)
                policy_id = loaded_json["policy_id"]
                access_rules = loaded_json["access_rules"]
                external_access = loaded_json["external_access"]
                policy_content = loaded_json["content"]

                log.logger.debug(f"正在导入策略 {policy_id}。")
                cur.execute(
                    "INSERT INTO `policies` VALUES(?, ?, ?, ?)",
                    (
                        policy_id,
                        json.dumps(policy_content),
                        json.dumps(access_rules),
                        json.dumps(external_access),
                    ),
                )
                log.logger.debug("导入成功完成。")

    log.logger.debug("所有策略的导入全部完成。")

    total_changes = (
        db_object.total_changes
        if isinstance(db_object, sqlite3.Connection)
        else "[Unavailable]"
    )

    log.logger.debug(f"正在提交，数据库修改量：{total_changes}")
    db_object.commit()

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
        fqueue_file.truncate(0)  # 清空

    fQueue_db = sqlite3.connect(root_abspath + "/content/fqueue.db")

    fQ_cur = fQueue_db.cursor()

    # create file transport queue table
    fQ_cur.execute(
        "CREATE TABLE ft_queue\
            (task_id TEXT, username TEXT, token TEXT, operation TEXT, file_id TEXT, fake_id TEXT, fake_dir TEXT, expire_time INTEGER, done INTEGER, cleared INTEGER)"
    )
    # file_id: 存贮在 document_indexes 中的文件id
    # fake_id: 这个 id 将作为 ftp 服务中以 task_id 为账户名的用户目录下的文件名。

    fQueue_db.close()

    ### Init FTP SSL

    from OpenSSL import crypto

    sr_class = secrets.SystemRandom()  # create SystemRandom class

    ###########
    # CA Cert #
    ###########

    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    ca_cert.set_serial_number(sr_class.randint(50000000, 100000000))

    ca_subj = ca_cert.get_subject()
    ca_subj.commonName = "CFMS Self CA"

    ca_cert.add_extensions(
        [
            crypto.X509Extension(
                b"subjectKeyIdentifier", False, b"hash", subject=ca_cert
            ),
        ]
    )

    ca_cert.add_extensions(
        [
            crypto.X509Extension(
                b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert
            ),
        ]
    )

    ca_cert.add_extensions(
        [
            crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
        ]
    )

    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_key)

    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

    ca_cert.sign(ca_key, "sha256")

    # Save certificate
    with open(f"{root_abspath}/content/auth/ca.crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode())

    # Save private key
    with open(f"{root_abspath}/content/auth/ca.key", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode())

    ###############
    # Client Cert #
    ###############

    client_key = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA, 2048)

    client_cert = crypto.X509()
    client_cert.set_version(2)
    client_cert.set_serial_number(sr_class.randint(50000000, 100000000))

    client_subj = client_cert.get_subject()
    client_subj.commonName = "CFMS Server self-signed"

    client_cert.add_extensions(
        [
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            crypto.X509Extension(
                b"subjectKeyIdentifier", False, b"hash", subject=client_cert
            ),
        ]
    )

    client_cert.add_extensions(
        [
            crypto.X509Extension(
                b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert
            ),
            crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth"),
            crypto.X509Extension(b"keyUsage", False, b"digitalSignature"),
        ]
    )

    client_cert.set_issuer(ca_subj)
    client_cert.set_pubkey(client_key)

    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

    client_cert.sign(ca_key, "sha256")

    # print(crypto.dump_certificate(crypto.FILETYPE_TEXT, client_cert))

    # Save certificate
    with open(f"{root_abspath}/content/auth/ftp_client.crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode())

    # Save private key
    with open(f"{root_abspath}/content/auth/ftp_client.key", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode())


# sock_condition = True


def mainloop(serverd):

    return

    created_count = 0

    # consoledThread = threading.Thread(target=consoled,name="consoled")
    # consoledThread.daemon = True # 解决不退出问题
    # consoledThread.start()

    while not terminate_event.is_set():
        # 建立客户端连接

        created_count += 1

        actives = threading.enumerate()

        thread_name = f"Thread-{created_count}"

        conn, addr = serverd.accept()
        keepalive = (1, 60 * 1000, 60 * 1000)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, True)  # 开启TCP保活
        conn.ioctl(socket.SIO_KEEPALIVE_VALS, keepalive)

        log.logger.info(f"connection address: {addr!s}")

        Thread = ConnThreads(
            target=ConnHandler,
            semaphore=sem,
            name=thread_name,
            args=(),
            kwargs={
                "conn": conn,
                "addr": addr,
                "toml_config": config,
                "root_abspath": root_abspath,
                "threading.terminate_event": terminate_event,
                "sys_locks": SYS_LOCKS,
                "db_pool": db_pool,
            },
        )
        Thread.daemon = True
        Thread.start()

    # 开始收尾工作
    log.logger.info("终止信号被激活，正在终止服务...")
    # terminate_event.set()

    wait_timeout = time.time() + config["exit"]["wait_sec"]

    while time.time() < wait_timeout:
        time.sleep(0.2)

        alive_threads = threading.enumerate()

        log.logger.debug(f"目前剩余的线程有：{alive_threads}")
        if len(threading.enumerate()) <= 2:  # 如果线程只有两个（主线程和 mainloop 必定在结果内）
            break

        log.logger.debug(f"等待 0.2s, 直到线程退出完毕 ... 超时时间：{wait_timeout}")

    log.logger.debug("正在退出 mainloop.")
    sys.exit()


def stopsocket():
    # socket终止
    terminate_event.set()
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host, port = "localhost", config["connect"]["port"]
    clientsocket.connect((host, port))
    clientsocket.close()

    sys.exit()


def consoled():
    """控制台
    若要添加控制台指令,在字典command_dict中添加即可"""
    log.logger.info("Command example: [command]; ")
    while True:
        try:
            i = input(">")
        except (EOFError, UnboundLocalError):
            pass
        if i.endswith(";"):
            command_dict = {
                "exit;": stopsocket,
            }
            command_dict[str(i)]()


# 获取初始绝对路径
# 结果最后不带斜杠，需要手动添加
root_abspath = os.path.dirname(os.path.abspath(__file__))

# print(root_abspath)
## 开始执行初始化过程

log = logtool.LogClass(logname="main", filepath="".join((root_abspath, "/main.log")))

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
        DEBUG = True

        log.cshandler.setLevel(logging.DEBUG)
        log.logger.info("Debug mode enabled.")
    
    log.logger.debug(f"config: {config}")

    starttime = time.time()  # 这里还有个endtime，但我懒得写了

    log.logger.info("Starting Classified File Management System - Server...")
    # log.logger.info(f"Server time:{starttime}")
    log.logger.info(f"Version {READABLE_VERSION}")
    log.logger.info("Running On: Python %s" % sys.version)
    if sys.version_info < (3, 11):  # 基于Python 3.11 开发，因此低于此版本就无法运行
        log.logger.fatal("您正在运行的 Python 版本低于本系统的最低要求 (>=3.11)。")
        log.logger.fatal("由于此原因，程序无法继续。")
        sys.exit()


    db_type = config["database"]["db_type"]

    db_pool = getDBPool(config)
    maindb = getDBConnection(db_pool)

    if db_type == "mysql":
        m_cur = maindb.cursor(prepared=True)
    else:
        m_cur = maindb.cursor()

    # print(type(maindb.conn))

    # 加载语言配置
    language = config["general"]["locale"]
    es = gettext.translation(
        "main", localedir="./include/locale", languages=[language], fallback=True
    )
    es.install()

    # 检查数据库存在性，没有就初始化

    # m_cur.execute("CREATE TABLE IF NOT EXISTS movie(title, year, score)")

    if db_type == "sqlite3":
        m_cur.execute("select 1 from sqlite_schema where type='table' order by name;")
    elif db_type == "mysql":
        _mysql_db_name = config["database"]["mysql_db_name"]
        m_cur.execute(
            "select 1 from information_schema.tables where table_schema = ? and table_name = 'cfms_internal';",
            (_mysql_db_name,),
        )
    if not m_cur.fetchone():
        dbInit(maindb)

    maindb.close()

    # 初始化 token_secret
    if config["security"]["update_token_secret_at_startup"]:
        with open(
            f"{root_abspath}/content/auth/token_secret", "+a"
        ) as ts_file:  # 这个文件的重要性和 pri.pem 是一样的
            ts_file.truncate(0)  # 清空
            ts_file.write(secrets.token_hex(128))

    # server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    ipv4_addr = (config["connect"]["ipv4_addr"], config["connect"]["port"])
    ipv6_addr = (config["connect"]["ipv6_addr"], config["connect"]["port"])

    semaphore_count = config["connect"]["max_handlers"]
    max_queue = config["connect"]["max_queued_connections"]

    sem = threading.Semaphore(semaphore_count)

    # if config["connect"]["ipv4_enabled"]:
    #     server.bind(ipv4_addr)
    #     server.listen(max_queue)
    # if config["connect"]["ipv6_enabled"]:
    #     server.bind(ipv6_addr)
    #     server.listen(max_queue)

    if config["connect"]["ipv4_enabled"]:
        log.logger.info((f"IPv4 Address: {ipv4_addr}"))
    else:
        log.logger.info(("IPv4 is not supported."))
    if config["connect"]["ipv6_enabled"]:
        log.logger.info((f"IPv6 Address: {ipv6_addr}"))
    else:
        log.logger.info(("IPv6 is not supported."))

    from include.experimental.server import ThreadedSocketServer, SocketHandler

    # 由于启动主服务会导致阻塞，因此所有线程操作必须提前启动

    # 初始化 FTPServer
    log.logger.info(f'正在初始化 FTP 服务... 端口开放在 {config["connect"]["ftp_port"]}.')
    FTPServerThread = threading.Thread(
        target=pyftpd.main,
        args=(
            root_abspath,
            terminate_event,
            (config["connect"]["ipv4_addr"], config["connect"]["ftp_port"]),
            SYS_LOCKS,
            db_pool,
        ),
        name="FTPServerThread",
    )
    FTPServerThread.start()

    # 初始化 Cron
    log.logger.info("正在注册计划任务...")
    SchedulerThread = threading.Thread(
        target=taskScheduler.main,
        args=(root_abspath, terminate_event, db_pool),
        name="SchedulerThread",
    )
    SchedulerThread.start()

    endtime = time.time()
    log.logger.info(f"完成（{endtime - starttime} s）！正在启动主要服务。")

    with ThreadedSocketServer(ipv4_addr, SocketHandler, server_config=config, db_pool=db_pool) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        # server._db_pool = db_pools
        server.serve_forever()

    

    # mainloopThread = threading.Thread(target=lambda: mainloop(server), name="mainloop")
    # mainloopThread.start()

    # mainloopThread.join()  # 主线程保活，以支持计划任务运行

    sys.exit()
