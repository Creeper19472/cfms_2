import json
import os
from typing import Iterable
import sqlite3
import secrets
import hashlib
import time
import datetime

from include.bulitin_class.errors import PendingWriteFileError
from include.database.operator import DatabaseOperator

__all__ = ['createFileIndex', 'createFileTask', 'cancelFileTask']

def createFileIndex(instance, new_index_id: str | None = None):

    with DatabaseOperator(instance._pool) as dboptr:

        # 开始创建文件

        index_file_id = (
            new_index_id if new_index_id else secrets.token_hex(64)
        )  # 存储在 document_indexes 中
        real_filename = secrets.token_hex(16)

        today = datetime.date.today()

        destination_path = (
            f"/content/files/{today.year}/{today.month}"
        )

        os.makedirs(destination_path, exist_ok=True)  # 即使文件夹已存在也加以继续

        with open(f"{destination_path}/{real_filename}", "w") as new_file:
            pass

        # 注册数据库条目

        # handle_cursor.execute("BEGIN TRANSACTION;")

        dboptr[1].execute(
            "INSERT INTO document_indexes (`id`, `path`) VALUES (?, ?)",
            (index_file_id, destination_path + "/" + real_filename),
        )

        dboptr[0].commit()

    return index_file_id

def createFileTask(
    instance,
    file_ids: Iterable,
    username,
    task_id=None,
    operation="read",
    expire_time=None,
    force_write=False,
):
    fqueue_db = sqlite3.connect(f"{instance.server.root_abspath}/content/fqueue.db")

    fq_cur = fqueue_db.cursor()

    if not task_id:
        task_id = secrets.token_hex(64)

    if expire_time == None:
        expire_time = time.time() + 3600  # by default

    token_hash = secrets.token_hex(64)
    token_salt = secrets.token_hex(16)

    token_hash_sha256 = hashlib.sha256(token_hash.encode()).hexdigest()
    final_token_hash_obj = hashlib.sha256()
    final_token_hash_obj.update((token_hash_sha256 + token_salt).encode())

    final_token_hash = final_token_hash_obj.hexdigest()

    token_to_store = (final_token_hash, token_salt)

    # fake_dir(set to task_id)
    fake_dir = task_id[32:]

    # Iterable: allocate fake_id for per file

    insert_list = []
    return_id_dict = {}  # file_id: fake_id

    for per_file_id in file_ids:
        this_fake_id = secrets.token_hex(16)

        if operation == "write":
            fq_cur.execute(
                'SELECT * FROM ft_queue WHERE file_id = ? AND operation = "write" AND done = 0 AND expire_time > ?;',
                (
                    per_file_id,
                    time.time(),
                ),
            )
            query_result = fq_cur.fetchall()

            if query_result and not force_write:
                raise PendingWriteFileError("文件存在至少一需要写入的任务，且该任务尚未完成")

        insert_list.append(
            (
                task_id,
                username,
                operation,
                json.dumps(token_to_store),
                this_fake_id,
                fake_dir,
                per_file_id,
                expire_time,
            )
        )

        return_id_dict[per_file_id] = this_fake_id

    fq_cur.executemany(
        "INSERT INTO ft_queue (task_id, username, operation, token, fake_id, fake_dir, file_id, expire_time, done, cleared) \
                    VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, 0, 0 );",
        insert_list,
    )

    fqueue_db.commit()
    fqueue_db.close()

    return task_id, token_hash_sha256, return_id_dict, expire_time

def cancelFileTask(instance, task_id):
    fqueue_db = sqlite3.connect(f"{instance.server.root_abspath}/content/fqueue.db")
    fq_cur = fqueue_db.cursor()

    fq_cur.execute(
        "SELECT FROM ft_queue WHERE task_id = ? AND done = 0 AND expire_time > ?",
        (task_id, time.time()),
    )
    query_result = fq_cur.fetchall()

    if not query_result:  # 如果任务已经完成，或并未存在
        return False

    fq_cur.execute(
        "UPDATE ft_queue SET done = -2 WHERE task_id = ? AND done = 0 AND expire_time > ?;",
        (task_id, time.time()),
    )
    fqueue_db.commit()
    fqueue_db.close()

    return True