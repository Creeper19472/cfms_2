# -*- coding:utf-8 -*-

CORE_VERSION = (1, 0, 0, "240324_alpha")
READABLE_VERSION = (
    f"{CORE_VERSION[0]}.{CORE_VERSION[1]}.{CORE_VERSION[2]}.{CORE_VERSION[3]}"
)


# import importlib

import logging
import sys, os, socket, gettext, time, threading
import tomllib
from include.initialize_scripts.initialize import initDatabaseStructure
import include.logtool as logtool
from include.connThread import *

import include.fileftp.pyftpd as pyftpd
import include.taskScheduler as taskScheduler

import secrets

# from apscheduler.schedulers.background import BackgroundScheduler
from include.database.abstracted import getDBConnection

from include.database.pool import getDBPool

# 开发模式开关
DEBUG = False


# 初始化 terminate_event
terminate_event = threading.Event()

SYS_IOLOCK = threading.RLock()

SYS_LOCKS = {"SYS_IOLOCK": SYS_IOLOCK}


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
        raise NotImplementedError("Since 1.0 other db types are not available.")
        # m_cur = maindb.cursor()

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
        initDatabaseStructure(db_pool)

    m_cur.close()
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

    sys.exit()
