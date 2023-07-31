import sys
import threading
from apscheduler.schedulers.background import BackgroundScheduler
import sqlite3
import tomllib
import json
import time
import logging
import warnings
import os
from include.logtool import getCustomLogger

def _permanentlyDeleteFile(fake_path_id, db_conn):
    g_cur = db_conn.cursor()

    # 查询文件信息

    g_cur.execute(
        "SELECT type , file_id FROM path_structures WHERE id = ?", (fake_path_id,)
    )
    query_result = g_cur.fetchall()

    if len(query_result) == 0:
        raise FileNotFoundError
    elif len(query_result) > 1:
        raise ValueError("在查询表 path_structures 时发现不止一条同路径 id 的记录")

    got_type, index_file_id = query_result[0]

    if got_type != "file":
        raise TypeError("删除的必须是一个文件")

    # 查询 document_indexes 表

    g_cur.execute(
        "SELECT abspath FROM document_indexes WHERE id = ?", (index_file_id,)
    )

    index_query_result = g_cur.fetchall()

    if len(index_query_result) == 0:
        raise FileNotFoundError(
            f"未发现在 path_structures 中所指定的文件 id '{index_file_id}' 的记录"
        )
    elif len(index_query_result) > 1:
        raise ValueError("在查询表 document_indexes 时发现不止一条同 id 的记录")

    file_abspath = index_query_result[0][0]

    if not file_abspath:
        raise ValueError("file_abspath 必须有值")

    # 删除表记录

    g_cur.execute("DELETE from document_indexes where id = ?;", (index_file_id,))
    g_cur.execute("DELETE from path_structures where id = ?;", (fake_path_id,))

    db_conn.commit()

    # 移除所有传输任务列表

    fq_db = sqlite3.connect(f"{ROOT_ABSPATH}/content/fqueue.db")
    fq_cur = fq_db.cursor()

    fq_cur.execute(
        "DELETE from ft_queue WHERE file_id = ? AND done = 0;", (index_file_id,)
    )  #  AND done = 0
    fq_db.commit()
    fq_db.close()

    # 删除真实文件

    os.remove(file_abspath)

    return True

def _permanentlyDeleteDir(path_id, db_conn): # 这将导致其下所有文件被永久删除，不判断是否被标记删除
    
    g_cur = db_conn.cursor()

    # 查询文件信息

    g_cur.execute(
        "SELECT type , id FROM path_structures WHERE parent_id = ?", (path_id,)
    )

    query_result = g_cur.fetchall()

    for i in query_result:
        this_object_type = query_result[0]
        this_object_id = query_result[1]

        if this_object_type == "dir":
            # db_conn.commit() # 以防万一先提交
            _permanentlyDeleteDir(this_object_id, db_conn) # 这要求函数尚未写入

        elif this_object_type == "file":
            _permanentlyDeleteFile(this_object_id, db_conn)

    return True

def task_clearExpiredFile():
    
    general_db = sqlite3.connect(f"{ROOT_ABSPATH}/general.db")          
    g_cur = general_db.cursor()

    g_cur.execute("SELECT id, state, type FROM path_structures where state like '%\"deleted\"%';")
    query_result = g_cur.fetchall()

    count = 0

    for i in query_result:
        this_object_id = i[0]
        this_object_state = json.loads(i[1])
        this_object_type = i[2]

        if this_object_state["expire_time"] < time.time():

            if this_object_type == "file":
                try:
                    _permanentlyDeleteFile(this_object_id, general_db)
                except FileNotFoundError:
                    logger.debug(f"指定的文件 (ID: {this_object_id} )已不存在。")
                
                logger.info(f"自动清理：删除了过期的文件 (ID: {this_object_id})")
                
            elif this_object_type == "dir":
                if _permanentlyDeleteDir(this_object_id, general_db):
                    logger.info(f"自动清理：删除了过期的文件夹 (ID: {this_object_id})，及其所有文件")
                else:
                    logger.error(f"自动清理文件夹 (ID: {this_object_id}) 时发生未知错误。")

            count += 1

    general_db.commit()

    if count:
        logger.info(f"过期文件清理完成，处理了 {count} 个项目")
    else:
        logger.info("过期文件清理完成，没什么要做的")


def main(root_abspath, terminate_event: threading.Event, logfile: str = "cron.log"):

    global ROOT_ABSPATH
    ROOT_ABSPATH = root_abspath

    global logger
    logger = getCustomLogger("main.cron", filepath="./content/logs/cron.log")

    aps_logger = logging.getLogger("apscheduler")
    aps_logger.setLevel(logging.DEBUG)

    # 初始化 BackgroundScheduler

    sch_logger = getCustomLogger("main.cron.scheduler", filepath="./content/logs/cron.log")

    global scheduler
    scheduler = BackgroundScheduler(logger=sch_logger)

    # logging.basicConfig(handlers=(lfhandler, cshandler), level=logger.debug)

    # 读取配置文件
    with open(f"{ROOT_ABSPATH}/config.toml", "rb") as f:
        config = tomllib.load(f)
    
    do_clean_job_interval = config["cron"]["do_clean_job_interval"]

    if do_clean_job_interval:

        # 初始化回收任务

        scheduler.add_job(task_clearExpiredFile, 'interval', seconds=do_clean_job_interval)

    else:
        logger.warn("已禁用垃圾回收任务。这可能导致标记删除的文件无法被自动处理。")
        warnings.warn("您确定设置是正确的吗? do_clean_job_interval 看起来被设置为\
                      空。请使用不为零的正数来设置其时间。", category=RuntimeWarning)
        
    # 启动调度器
    scheduler.start()
    # print(aps_logger.handlers)

    while not terminate_event.is_set():
        time.sleep(1)

    logger.info("正在退出计划任务调度器。")

    scheduler.shutdown()
    sys.exit()