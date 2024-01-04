
import os
import sqlite3
import uuid
from include.bulitin_class.policies import Policies
from include.bulitin_class.users import Users
from include.connThread import PendingWriteFileError

from include.database.operator import DatabaseOperator
# from include.experimental.server import SocketHandler

import time
import json

from include.util.convert import convertFile2PathID

from include.util.filetasks import createFileIndex, createFileTask, cancelFileTask

# 由于 sockethandler 不能循环导入，所以实际运行的代码不能有相应类型注释

def permanentlyDeleteFile(instance, fake_path_id):  # TODO #15 更新操作至适配 revision 的版本
    
    with DatabaseOperator(instance._pool) as dboptr:

        # 查询文件信息

        dboptr[1].execute(
            "SELECT `type`, `revisions` FROM path_structures WHERE `id` = ?",
            (fake_path_id,),
        )
        query_result = dboptr[1].fetchall()

        if len(query_result) == 0:
            raise FileNotFoundError
        elif len(query_result) > 1:
            raise ValueError("在查询表 path_structures 时发现不止一条同路径 id 的记录")

        got_type, revisions = query_result[0]

        revisions = json.loads(revisions)

        if got_type != "file":
            raise TypeError("删除的必须是一个文件")

        # 先初始化 fq_db
        fq_db = sqlite3.connect(f"{instance.server.root_abspath}/content/fqueue.db")
        fq_cur = fq_db.cursor()

        # 查询 document_indexes 表

        for revision_id in revisions:
            this_index_file_id = revisions[revision_id]["file_id"]

            dboptr[1].execute(
                "SELECT `abspath` FROM document_indexes WHERE `id` = ?",
                (this_index_file_id,),
            )

            index_query_result = dboptr[1].fetchall()

            if len(index_query_result) == 0:
                raise FileNotFoundError(
                    f"在处理 Rev ID: {revision_id} 的删除时，未发现在 path_structures 中所指定的文件 id '{this_index_file_id}' 的记录"
                )
            elif len(index_query_result) > 1:
                raise ValueError(
                    f"在处理 Rev ID: {revision_id} 的删除时，在查询表 document_indexes 时发现不止一条同 id 的记录"
                )

            file_abspath = index_query_result[0][0]

            if not file_abspath:
                raise ValueError("file_abspath 必须有值")

            # 删除表记录

            dboptr[1].execute(
                "DELETE from `document_indexes` where `id` = ?;", (this_index_file_id,)
            )
            dboptr[1].execute(
                "DELETE from `path_structures` where `id` = ?;", (fake_path_id,)
            )

            dboptr[0].commit()

            # 移除所有传输任务列表

            fq_db = sqlite3.connect(f"{instance.root_abspath}/content/fqueue.db")
            fq_cur = fq_db.cursor()

            fq_cur.execute(
                "DELETE from ft_queue WHERE file_id = ? AND done = 0;",
                (this_index_file_id,),
            )  #  AND done = 0

            # 删除真实文件
            os.remove(file_abspath)

            fq_cur.close()
            fq_db.commit()
            fq_db.close()

    return True

# def handle_operateFile(instance: SocketHandler, loaded_recv, user: Users):
def handle_operateFile(instance, loaded_recv, user: Users):

    if "data" not in loaded_recv:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if not loaded_recv["data"].get("action", None):
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    file_id: str = loaded_recv["data"].get("file_id", None)  # 伪路径文件 ID
    view_deleted = loaded_recv["data"].get("view_deleted", False)

    # 处理 revision_id
    specified_revision_id = loaded_recv["data"].get("revision_id", None)

    if not file_id:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if loaded_recv["data"]["action"] == "recover":
        view_deleted = True  # 若要恢复文件，则必须有权访问被删除的文件

    if view_deleted:  # 如果启用 view_deleted 选项
        if not user.hasRights(("view_deleted",)):
            instance.respond(**instance.RES_ACCESS_DENIED)
            return

    with DatabaseOperator(instance._pool) as dboptr:
        dboptr[1].execute(
            "SELECT `name`, `parent_id`, `type`, `revisions`, `access_rules`, `external_access`, `properties`, `state` \
                                FROM path_structures WHERE `id` = ?",
            (file_id,),
        )

        result = dboptr[1].fetchall()

    del dboptr # 避免识别上误以为已经定义

    if len(result) > 1:
        raise ValueError("Invaild query result length")
    elif len(result) < 1:
        instance.respond(**{"code": -1, "msg": "no such file"})
        return

    # 判断文档总体是否被删除
    if (file_state := json.loads(result[0][7]))["code"] == "deleted":
        # 如下，file_state 不一定是 file 的 state，但由于安全性原因只能先写这个判断
        if not view_deleted:
            instance.respond(**instance.RES_NOT_FOUND)
            return

    # 判断文档是否是个文档（雾）
    if result[0][2] != "file":
        instance.respond(-1, msg="not a file")
        return

    # 获取请求的操作
    req_action = loaded_recv["data"]["action"]

    # 首先判断该操作是否由文档所允许（但可能放在后面也行）
    if not instance.verifyUserAccess(file_id, req_action, user, _subcall=False):
        instance.respond(**instance.RES_ACCESS_DENIED)
        instance.logger.debug("权限校验失败：无权在文档下执行所请求的操作")
        return

    # 查询文档下的所有历史版本
    query_revisions: dict = json.loads(result[0][3])

    if not specified_revision_id:  # 如果未指定 rev
        newest_revision = ()  # by default

        # 排序
        sorted_revisions: list = sorted(
            query_revisions.items(), key=lambda i: i[1]["time"], reverse=True
        )

        # 如果已经删除
        for per_revision in sorted_revisions:  # per_revision is a tuple
            if per_revision[1]["state"]["code"] == "deleted":  # 我们假定用户希望得到最新的版本是未被删除的
                continue
            # 指定 newest
            newest_revision = per_revision
            break

        if not newest_revision and req_action in [
            "read",
            "delete_rev",
            "recover_rev",
        ]:  # 如果没有满足条件的 newest_revision
            instance.respond(**instance.RES_NOT_FOUND)
            return

        specified_revision_id, specified_revision_data = (
            newest_revision if newest_revision else (None, None)
        )  # 指定

    else:  # 如果已经指定
        # 判断是否有该 rev
        if specified_revision_id not in query_revisions:
            instance.respond(
                404, msg="specified revision not found"
                )
            return

        # 判断 rev 版本是否被删除（在特别指定了 rev_id 的时候才会出现）

        if query_revisions[specified_revision_id]["state"] == "deleted":
            if not view_deleted:
                instance.respond(
                    404, msg="specified revision not found"
                )
                return

        specified_revision_data: dict = query_revisions[specified_revision_id]

    # 正式处理对文件的操作，实际指向确定的 rev
    # 获取 revision <- getFileRevisions()

    instance.logger.debug(f"请求对文件版本ID {specified_revision_id} 的操作：{req_action}")

    if req_action in [
        "read",
        "write",
        "rename",
        "delete",
        "permanently_delete",
        "recover",
        "move",
        "change_id",
        "delete_rev",
        "recover_rev",
    ]:
        # 注意：write 操作仅支持覆盖，创建请使用 uploadFile

        # 在检查文档整体的权限的同时检查对特定版本的权限
        if not instance._verifyAccess(
            user,
            req_action,
            specified_revision_data["access_rules"],
            specified_revision_data["external_access"],
        ):
            instance.respond(**instance.RES_ACCESS_DENIED)
            instance.logger.debug("权限校验失败：无权在该历史版本执行所请求的操作")
            return

        specified_revision_file_id: str = specified_revision_data["file_id"]

        if req_action == "read":
            # 权限检查已在上一步完成

            (
                task_id,
                task_token,
                fake_file_ids,
                expire_time,
            ) = createFileTask(
                instance,
                (specified_revision_file_id,),
                operation="read",
                expire_time=time.time() + 3600,
                username=user.username,
            )

            mapping = {file_id: specified_revision_file_id}  # 伪路径文件ID: 该版本 index 表 文件ID

            response = {
                "code": 0,
                "msg": "ok",
                "data": {
                    "task_id": task_id,
                    "task_token": task_token,  # original hash after sha256
                    "expire_time": expire_time,
                    "t_filename": convertFile2PathID(fake_file_ids, mapping),
                },
            }

            instance.respond(**response)

        elif req_action == "write":  # 该操作将使得最新版本的 revision 指向给定的文件
            do_force_write = loaded_recv["data"].get("force_write", False)

            if file_state_code := file_state["code"] != "ok":
                if file_state_code == "locked":
                    instance.respond(
                        -1,
                        msg="file locked",
                        data={
                            "expire_time": file_state.get("expire_time", 0)
                        },                
                    )

                elif file_state_code == "deleted":
                    instance.respond(
                        -1,
                        msg = "The file has been marked for deletion, please restore it first",
                        data = {
                            "expire_time": file_state.get("expire_time", 0)
                        },        
                    )
                    

                else:
                    instance.respond(
                        -1, msg="unexpected file status"
                    )

                return

            ### 创建一个新的 revision

            # 得到新的随机文件ID，此时文件应当已创建
            new_revision_file_id: str = createFileIndex(instance)

            # 构造
            new_revision_id: str = uuid.uuid4().hex
            new_revision_data = {
                "file_id": new_revision_file_id,
                "state": {"code": "ok", "expire_time": 0},
                "access_rules": {},
                "external_access": {},
                "time": time.time(),
            }

            ## 写入新的 revision

            # 开启事务
            # handle_cursor.execute("BEGIN TRANSACTION;")

            with DatabaseOperator(instance._pool) as dboptr:

                # 读取
                dboptr[1].execute(
                    "SELECT `revisions` FROM path_structures WHERE `id` = ?", (file_id,)
                )
                _revisions_now = json.loads(
                    dboptr[1].fetchone()[0]
                )  # 由于主键的互异性，此处应该仅有一条结果

                _insert_revisions = _revisions_now
                _insert_revisions[new_revision_id] = new_revision_data

                dboptr[1].execute(
                    "UPDATE path_structures SET `revisions` = ? WHERE `id` = ?; ",
                    (json.dumps(_insert_revisions), file_id),
                )

                dboptr[0].commit()

            del dboptr

            ## 创建传输任务

            try:
                (
                    task_id,
                    task_token,
                    fake_file_ids,
                    expire_time,
                ) = createFileTask(
                    instance,
                    (new_revision_file_id,),
                    operation="write",
                    expire_time=time.time() + 3600,
                    force_write=do_force_write,
                    username=user.username,
                )
            except PendingWriteFileError:
                instance.respond(**{"code": -1, "msg": "file already in use"})
                return

            mapping = {file_id: new_revision_file_id}

            response = {
                "code": 0,
                "msg": "ok",
                "data": {
                    "task_id": task_id,
                    "task_token": task_token,  # original hash after sha256
                    "expire_time": expire_time,
                    "t_filename": convertFile2PathID(
                        fake_file_ids, mapping
                    ),  # 这个ID是客户端上传文件时应当使用的文件名
                },
            }

            instance.respond(**response)

        elif req_action == "rename":
            new_filename = loaded_recv["data"].get("new_filename", None)

            if not new_filename:  # filename 不能为空
                instance.respond(**instance.RES_MISSING_ARGUMENT)
                return

            if file_state_code := file_state["code"] != "ok":
                if file_state_code == "locked":
                    instance.respond(    
                        -1,
                        msg = "file locked",
                        data = {
                            "expire_time": file_state.get("expire_time", 0)
                        },
                    )
                    return
                
            with DatabaseOperator(instance._pool) as dboptr:

                dboptr[1].execute(
                    "UPDATE path_structures SET `name` = ? WHERE `id` = ?;",
                    (new_filename, file_id),
                )

                dboptr[0].commit()

            del dboptr

            instance.respond(**{"code": 0, "msg": "success"})

        elif req_action == "delete":

            with DatabaseOperator(instance._pool) as dboptr:

                recycle_policy = Policies("recycle", *dboptr)
                delete_after_marked_time = recycle_policy["deleteAfterMarked"]

                if file_state["code"] == "deleted":
                    instance.send(
                        json.dumps(
                            {
                                "code": -1,
                                "msg": "The file has been marked for deletion",
                            }
                        )
                    )
                    return

                new_state = {
                    "code": "deleted",
                    "expire_time": time.time() + delete_after_marked_time,
                }

                dboptr[1].execute(
                    "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
                    (json.dumps(new_state), file_id),
                )

                dboptr[0].commit()

            del dboptr

            instance.respond(**instance.RES_OK)

        elif req_action == "recover":
            if file_state["code"] != "deleted":
                instance.respond(**{"code": -1, "msg": "File is not deleted"})
                return

            recovered_state = {"code": "ok", "expire_time": 0}

            with DatabaseOperator(instance._pool) as dboptr:
                dboptr[1].execute(
                    "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
                    (json.dumps(recovered_state), file_id),
                )

                dboptr[0].commit()

            del dboptr

            instance.respond(**instance.RES_OK)

        elif req_action == "permanently_delete":
            permanentlyDeleteFile(instance, file_id)
            instance.respond(**instance.RES_OK)

        elif req_action == "move":
            new_parent_id = loaded_recv["data"].get("new_parent", None)

            if new_parent_id == None:
                instance.respond(**instance.RES_MISSING_ARGUMENT)
                return

            # 判断新目录是否存在

            with DatabaseOperator(instance._pool) as dboptr:

                dboptr[1].execute(
                    "SELECT `type` FROM path_structures WHERE `id` = ?",
                    (new_parent_id,),
                )

                query_result = dboptr[1].fetchall()

                if len(query_result) == 0:
                    instance.respond(**instance.RES_NOT_FOUND)
                    return
                elif len(query_result) != 1:
                    raise ValueError("意料之外的记录数量")

                if query_result[0][0] != "dir":
                    instance.respond(**{"code": -1, "msg": "新的路径不是一个目录"})
                    return

                # 调取原目录

                dboptr[1].execute(
                    "SELECT `parent_id` FROM path_structures WHERE `id` = ?",
                    (file_id,),
                )

                old_parent_result = dboptr[1].fetchone()

                old_parent_id = old_parent_result[0]

                if not instance.verifyUserAccess(
                    new_parent_id, "write", user
                ) or not instance.verifyUserAccess(old_parent_id, "delete", user):
                    # 移动操作实际上是向新目录写入文件，并删除旧目录文件

                    instance.respond(**instance.RES_ACCESS_DENIED)
                    return

                # 执行操作

                dboptr[1].execute(
                    "UPDATE path_structures SET `parent_id` = ? WHERE `id` = ?;",
                    (new_parent_id, file_id),
                )

                dboptr[0].commit()

            del dboptr

            instance.respond(**instance.RES_OK)
            return

        elif req_action == "change_id":
            if not user.hasRights(("change_id",)):
                instance.respond(**instance.RES_ACCESS_DENIED)
                return

            new_id = loaded_recv["data"].get("new_id", None)

            if not new_id:  # id 不能为空
                instance.respond(**instance.RES_MISSING_ARGUMENT)
                return

            # 判断新 ID 是否被使用

            with DatabaseOperator(instance._pool) as dboptr:

                dboptr[1].execute(
                    "SELECT `type` FROM path_structures WHERE `id` = ?", (new_id,)
                )

                result = dboptr[1].fetchall()

                if result:
                    instance.respond(**{"code": -1, "msg": "id exists"})
                    return

                # 执行操作

                dboptr[1].execute(
                    "UPDATE path_structures SET `id` = ? WHERE `id` = ?;",
                    (new_id, file_id),
                )

                dboptr[0].commit()

            del dboptr

            instance.respond(**instance.RES_OK)
            return

        elif req_action == "delete_rev":  # 删除指定的修订
            with DatabaseOperator(instance._pool) as dboptr:
                recycle_policy = Policies("recycle", *dboptr)
                rev_delete_after_marked_time = recycle_policy["revDeleteAfterMarked"]

                if specified_revision_data["state"]["code"] == "deleted":
                    instance.respond(**{"code": -1, "msg": "already deleted"})
                    return

                # 执行事务

                # handle_cursor.execute("BEGIN TRANSACTION;")

                # 读取
                dboptr[1].execute(
                    "SELECT `revisions` FROM path_structures WHERE `id` = ?", (file_id,)
                )
                _revisions_now = json.loads(
                    dboptr[1].fetchone()[0]
                )  # 由于主键的互异性，此处应该仅有一条结果

                # 构造写入

                _revisions_now[specified_revision_id]["state"] = {
                    "code": "deleted",
                    "expire_time": time.time() + rev_delete_after_marked_time,
                }

                dboptr[1].execute(
                    "UPDATE path_structures SET `revisions` = ? WHERE `id` = ?;",
                    (_revisions_now, file_id),
                )

                # handle_cursor.execute("COMMIT TRANSACTION;")
                dboptr[1].commit()

            del dboptr

            instance.respond(**instance.RES_OK)
            return

        elif req_action == "recover_rev":
            if specified_revision_data["state"]["code"] != "deleted":
                instance.respond(
                    **{"code": -1, "msg": "Specified revision is not deleted"}
                )
                return

            recovered_state = {"code": "ok", "expire_time": 0}

            with DatabaseOperator(instance._pool) as dboptr:

                # 执行事务

                # handle_cursor.execute("BEGIN TRANSACTION;")

                # 读取
                dboptr[1].execute(
                    "SELECT `revisions` FROM path_structures WHERE `id` = ?", (file_id,)
                )
                _revisions_now = json.loads(
                    dboptr[1].fetchone()[0]
                )  # 由于主键的互异性，此处应该仅有一条结果

                # 构造写入

                _revisions_now[specified_revision_id]["state"] = recovered_state

                dboptr[1].execute(
                    "UPDATE path_structures SET `revisions` = ? WHERE `id` = ?;",
                    (_revisions_now, file_id),
                )

                # handle_cursor.execute("COMMIT TRANSACTION;")
                dboptr[0].commit()

            del dboptr

            instance.respond(**instance.RES_OK)
            return

    else:
        instance.respond(**{"code": -1, "msg": "operation not found"})
        instance.logger.debug("请求的操作不存在。")
        return
