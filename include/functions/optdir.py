from collections import UserList
import secrets
from include.bulitin_class.policies import Policies
from include.bulitin_class.users import Users
from include.connThread import PendingWriteFileError

from include.database.operator import DatabaseOperator
# from include.experimental.server import SocketHandler

import time
import json


def handle_getRootDir(instance, loaded_recv, user: Users):

    with DatabaseOperator(instance._pool) as couple:

        por_policy = Policies("permission_on_rootdir", *couple)

        por_access_rules = por_policy["rules"]["access_rules"]
        por_external_access = por_policy["rules"]["external_access"]

        # 增加对 view_deleted 的判断
        view_deleted = loaded_recv["data"].get("view_deleted", False)

        if view_deleted:  # 如果启用 view_deleted 选项
            if not user.hasRights(("view_deleted",)):
                instance.respond(**instance.RES_ACCESS_DENIED)
                return

        if not instance._verifyAccess(
            user, "read", por_access_rules, por_external_access, True
        ):
            instance.logger.debug("用户无权访问根目录")
            instance.respond(**{"code": 403, "msg": "forbidden"})
            return
        else:
            instance.logger.debug("根目录鉴权成功")

        # couple[1] = None

        couple[1].execute(
            "SELECT `id`, `name`, `type`, `properties`, `state` FROM path_structures WHERE `parent_id` = ?",
            ("",),
        )
        all_result = couple[1].fetchall()

        dir_result = dict()

        for i in all_result:
            this_object_state = json.loads(i[4])

            if this_object_state["code"] == "deleted":
                if not view_deleted:
                    continue

            if not instance.verifyUserAccess(i[0], "read", user):  # 检查该目录下的文件是否有权访问，如无则隐藏
                if instance.config["security"]["hide_when_no_access"]:
                    continue
                else:
                    pass

            original_properties = json.loads(i[3])

            filtered_properties = instance.filterPathProperties(original_properties)

            if i[2] == "file":
                filtered_properties["size"] = instance.getFileSize(i[0])

            # print(i)
            dir_result[i[0]] = {
                "name": i[1],
                "type": i[2],
                "state": this_object_state,
                "properties": filtered_properties,
            }

        instance.respond(**{"code": 0, "dir_data": dir_result})

        return

# def handle_operateDir(instance: SocketHandler, loaded_recv, user: Users):
def handle_operateDir(instance, loaded_recv, user: Users):    
    if "data" not in loaded_recv:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if not (action := loaded_recv["data"].get("action", None)):
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if not (dir_id := loaded_recv["data"].get("dir_id", None)):
        instance.respond(**{"code": -1, "msg": "need a dir id"})
        return

    view_deleted = loaded_recv["data"].get("view_deleted", False)

    if loaded_recv["data"]["action"] == "recover":
        view_deleted = True  # 若要恢复文件，则必须有权访问被删除的文件

    if view_deleted:  # 如果启用 view_deleted 选项
        if not user.hasRights(("view_deleted",)):
            instance.respond(**instance.RES_ACCESS_DENIED)
            return

    dboptr: UserList = DatabaseOperator(instance._pool)

    dboptr[1].execute(
        'SELECT `name`, `parent_id`, `access_rules`, `external_access`, `properties`, `state` \
                            FROM path_structures WHERE `id` = ? AND `type` = "dir";',
        (dir_id,),
    )

    result = dboptr[1].fetchall()

    # print(result)

    if len(result) > 1:
        raise ValueError("Invaild query result length")
    elif len(result) < 1:
        instance.respond(**{"code": -1, "msg": "no such dir"})
        return
    else:
        if (dir_state := json.loads(result[0][5]))["code"] == "deleted":
            # 如下，file_state 不一定是 file 的 state，但由于安全性原因只能先写这个判断
            if not view_deleted:
                instance.respond(**instance.RES_NOT_FOUND)
                return

    parent_id = result[0][1]  # 文件夹的父级目录 ID

    if action in [
        "list",
        "delete",
        "permanently_delete",
        "rename",
        "recover",
        "move",
        "change_id",
    ]:
        # 鉴权
        if not instance.verifyUserAccess(dir_id, action, user, _subcall=False):
            instance.respond(**{"code": 403, "msg": "permission denied"})
            instance.logger.debug("权限校验失败：无权执行所请求的操作")
            return

        if action == "list":
            dboptr[1].execute(
                "SELECT `id`, `name`, `type`, `properties`, `state` FROM path_structures WHERE `parent_id` = ?",
                (dir_id,),
            )
            all_result = dboptr[1].fetchall()

            dir_result = dict()

            for i in all_result:
                this_object_state = json.loads(i[4])

                if this_object_state["code"] == "deleted":  # 如果已被删除
                    if not view_deleted:
                        continue

                if not instance.verifyUserAccess(
                    i[0], "read", user
                ):  # 检查该目录下的文件是否有权访问，如无则隐藏
                    if instance.server.config["security"]["hide_when_no_access"]:
                        continue
                    else:
                        pass

                original_properties = json.loads(i[3])

                filtered_properties = instance.filterPathProperties(original_properties)

                if i[2] == "file":
                    filtered_properties["size"] = instance.getFileSize(i[0])

                # print(i)
                dir_result[i[0]] = {
                    "name": i[1],
                    "type": i[2],
                    "state": this_object_state,  # dict
                    "properties": filtered_properties,
                }

            por_policy = Policies("permission_on_rootdir", *dboptr)

            if parent_id:
                if instance.verifyUserAccess(parent_id, "read", user):  # 检查是否有权访问父级目录
                    dboptr[1].execute(
                        "SELECT `name`, `type`, `properties` FROM path_structures WHERE `id` = ?",
                        (parent_id,),
                    )
                    parent_result = dboptr[1].fetchone()

                    parent_properties = json.loads(parent_result[2])

                    if parent_result[1] != "dir":
                        raise RuntimeError("父级目录并非一个文件夹")

                    dir_result[parent_id] = {
                        "name": parent_result[0],
                        "type": "dir",
                        "parent": True,
                        "properties": instance.filterPathProperties(parent_properties),
                    }

            else:  # 如果父级目录是根目录，检查是否有权访问根目录
                instance.logger.debug(f"目录 {dir_id} 的上级目录为根目录。正在检查用户是否有权访问根目录...")

                por_access_rules = por_policy["rules"]["access_rules"]
                por_external_access = por_policy["rules"]["external_access"]

                if not instance._verifyAccess(
                    user, "read", por_access_rules, por_external_access, True
                ):
                    instance.logger.debug("用户无权访问根目录")
                else:
                    instance.logger.debug("根目录鉴权成功")

                    dir_result[""] = {
                        "name": "<root directory>",
                        "type": "dir",
                        "parent": True,
                        "properties": {}
                        # "properties": instance.filterPathProperties(parent_properties)
                    }

            instance.respond(**{"code": 0, "dir_data": dir_result})

        elif action == "delete":
            recycle_policy = Policies("recycle", *dboptr)
            delete_after_marked_time = recycle_policy["deleteAfterMarked"]

            if dir_state["code"] == "deleted":
                instance.send(
                    json.dumps(
                        {
                            "code": -1,
                            "msg": "The directory has been marked for deletion",
                        }
                    )
                )
                return

            succeeded, failed = deleteDir(
                instance, dir_id, user, delete_after=delete_after_marked_time
            )

            if failed:
                response_code = -3  # 请求已经完成，但有错误
            else:
                response_code = 0

            response = {
                "code": response_code,
                "msg": "request processed",
                "data": {"succeeded": succeeded, "failed": failed},
            }

            instance.respond(**response)

        elif action == "permanently_delete":
            pass

        elif action == "rename":
            new_dirname = loaded_recv["data"].get("new_dirname", None)

            if not new_dirname:  # dirname 不能为空
                instance.respond(**instance.RES_MISSING_ARGUMENT)
                return

            if dir_state_code := dir_state["code"] != "ok":
                if dir_state_code == "locked":
                    instance.send(
                        json.dumps(
                            {
                                "code": -1,
                                "msg": "directory is locked",
                                "data": {
                                    "expire_time": dir_state.get("expire_time", 0)
                                },
                            }
                        )
                    )
                    return

            dboptr[1].execute(
                "UPDATE path_structures SET `name` = ? WHERE `id` = ?;",
                (new_dirname, dir_id),
            )

            dboptr[0].commit()

            instance.respond(**{"code": 0, "msg": "success"})

        elif action == "recover":  # 会恢复其下的所有内容，无论其是否因删除此文件夹而被删除
            if dir_state["code"] != "deleted":
                instance.respond(**{"code": -1, "msg": "Directory is not deleted"})
                return

            succeeded, failed = recoverDir(instance, dir_id, user)

            if failed:
                response_code = -3  # 请求已经完成，但有错误
            else:
                response_code = 0

            response = {
                "code": response_code,
                "msg": "request processed",
                "data": {"succeeded": succeeded, "failed": failed},
            }

            instance.respond(**response)

        elif action == "move":  # 基本同 operateFile 的判断
            new_parent_id = loaded_recv["data"].get("new_parent", None)

            if new_parent_id == None:  # 因为根目录的id为空
                instance.respond(**instance.RES_MISSING_ARGUMENT)
                return

            if new_parent_id == dir_id:
                instance.respond(**{"code": -2, "msg": "一个目录的父级目录不能指向它自己"})
                return

            # 判断新目录是否存在

            dboptr[1] = instance.db_cursor

            dboptr[1].execute(
                "SELECT `type` FROM path_structures WHERE `id` = ?",
                (new_parent_id,),
            )

            query_result = dboptr[1].fetchall()

            if len(query_result) == 0:
                instance.respond(**{"code": 404, "msg": "没有找到请求的新目录"})
                return
            elif len(query_result) != 1:
                raise ValueError("意料之外的记录数量")

            if query_result[0][0] != "dir":
                instance.respond(**{"code": -1, "msg": "新的路径不是一个目录"})
                return

            # 调取原目录

            dboptr[1].execute(
                "SELECT `parent_id` FROM path_structures WHERE `id` = ?", (dir_id,)
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
                (new_parent_id, dir_id),
            )
            # 不需要对下级文件做其他操作

            instance.db_conn.commit()

            instance.respond(**instance.RES_OK)

            return

        elif action == "change_id":
            if not user.hasRights(("change_id",)):
                instance.respond(**instance.RES_ACCESS_DENIED)
                return

            new_id = loaded_recv["data"].get("new_id", None)

            if not new_id:
                instance.respond(**instance.RES_MISSING_ARGUMENT)
                return

            if new_id == dir_id:  # 如果和原ID一致，用于减少数据库开销
                instance.respond(**{"code": 0, "msg": "no changes made"})
                return

            # 判断新 ID 是否被使用

            dboptr[1] = instance.db_cursor

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
                (new_id, dir_id),
            )

            instance.db_conn.commit()

            instance.respond(**instance.RES_OK)

            return

    else:
        instance.respond(**instance.RES_BAD_REQUEST)

def handle_createDir(instance, loaded_recv, user: Users):
    if "data" not in loaded_recv:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if not user.hasRights(("create_dir",)):  # 鉴权
        instance.respond(**instance.RES_ACCESS_DENIED)
        return

    target_parent_id = loaded_recv["data"].get(
        "parent_id", ""
    )  # fallback to rootdir
    target_id = loaded_recv["data"].get("dir_id", None)
    new_dirname = loaded_recv["data"].get("name", None)

    if not new_dirname:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if target_id:  # 自动生成
        if len(target_id) > 64:
            instance.respond(**{"code": -1, "msg": "directory id too long"})
            return
    else:
        target_id = secrets.token_hex(16)

    ### 从这里继续
        
    with DatabaseOperator(instance._pool) as dboptr:

        dboptr[1].execute(
            "SELECT 1 FROM path_structures WHERE `id` = ?", (target_id,)
        )

        query_result = dboptr[1].fetchall()

        if query_result:
            instance.respond(
               
                **{
                    "code": -1,
                    "msg": "file or directory exists.",
                    "__hint__": "if you want to override a directory, use 'operateDir' instead.",
                }

            )
            return

        del query_result  # 清除

        if target_parent_id:  # 如果不是根目录
            dboptr[1].execute(
                "SELECT `type` FROM path_structures WHERE `id` = ?", (target_parent_id,)
            )

            dir_query_result = dboptr[1].fetchall()

            if not dir_query_result:
                instance.respond(
                    **{"code": 404, "msg": "target directory not found"}
                )
                return
            elif len(dir_query_result) > 1:
                raise RuntimeError("数据库出现了不止一条同id的记录")

            if (d_id_type := dir_query_result[0][0]) != "dir":
                instance.logger.debug(
                    f"用户试图请求在 id 为 {target_parent_id} 的目录下创建子目录，\
                                    但它事实上不是一个目录（{d_id_type}）"
                )
                instance.respond(**{"code": -1, "msg": "not a directory"})
                return

            if not instance.verifyUserAccess(target_parent_id, "write", user):
                instance.respond(**instance.RES_ACCESS_DENIED)
                return

        else:
            por_policy = Policies("permission_on_rootdir", *dboptr)

            por_access_rules = por_policy["rules"]["access_rules"]
            por_external_access = por_policy["rules"]["external_access"]

            if not instance._verifyAccess(
                user, "write", por_access_rules, por_external_access, True
            ):
                instance.logger.debug("用户无权访问根目录")
                instance.respond(**instance.RES_ACCESS_DENIED)
                return
            else:
                instance.logger.debug("根目录鉴权成功")

        # 开始创建文件夹

        # 注册数据库条目

        dboptr[1].execute(
            "INSERT INTO path_structures \
                                (`id` , `name`, `owner` , `parent_id` , `type` , `revisions` , `access_rules`, `external_access`, `properties`, `state`) \
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (
                target_id,
                new_dirname,
                json.dumps((("user", user.username),)),
                target_parent_id,
                "dir",
                None,
                r"{}",
                r"{}",
                json.dumps({"created_time": time.time()}),
                json.dumps({"code": "ok", "expire_time": 0}),
            ),
        )

        dboptr[0].commit()

        instance.respond(
            **{"code": 0, "msg": "directory created", "data": {"dir_id": target_id}}
        )

        return

def deleteDir(instance, dir_id, user: Users, delete_after=0, dboptr: DatabaseOperator = None):

    if not dboptr:
        dboptr = DatabaseOperator(instance._pool)

    completed_list = []
    failed_list = []

    new_state = {"code": "deleted", "expire_time": time.time() + delete_after}

    # 判断是否有权限

    # 遍历下级文件夹
    dboptr[1].execute(
        'SELECT `id` FROM path_structures WHERE `parent_id` = ? AND `type` = "dir";',
        (dir_id,),
    )

    query_subs_result = dboptr[1].fetchall()

    for i in query_subs_result:
        sub_result = deleteDir(instance, i[0], user, dboptr=dboptr)

        completed_list += sub_result[0]
        failed_list += sub_result[1]

    # 获取本级列表
    dboptr[1].execute(
        "SELECT `id` FROM path_structures WHERE `parent_id` = ?", (dir_id,)
    )
    query_result = dboptr[1].fetchall()

    for i in query_result:
        if not instance.verifyUserAccess(i[0], "delete", user):
            failed_list.append(i[0])
        else:
            # 删除该目录的直系子级文件和目录
            dboptr[1].execute(
                "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
                (json.dumps(new_state), i[0]),
            )
            completed_list.append(i[0])

    if not failed_list:  # 仅当删除下级文件未出现错误时才删除目录
        dboptr[1].execute(
            "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
            (json.dumps(new_state), dir_id),
        )
        completed_list.append(dir_id)
    else:
        failed_list.append(dir_id)

    dboptr[0].commit()

    del dboptr

    return completed_list, failed_list

def recoverDir(instance, dir_id, user: Users, dboptr: DatabaseOperator = None):
    # 注意：前后两个函数都不对用户是否有该文件夹权限做判断，应在 handle 部分完成

    if not dboptr:
        dboptr = DatabaseOperator(instance._pool)

    completed_list = []
    failed_list = []

    new_state = {"code": "ok", "expire_time": 0}

    # 判断是否有权限

    # 遍历下级文件夹
    dboptr[1].execute(
        'SELECT `id` FROM path_structures WHERE `parent_id` = ? AND `type` = "dir";',
        (dir_id,),
    )

    query_subs_result = dboptr[1].fetchall()

    for i in query_subs_result:
        sub_result = recoverDir(instance, i[0], user, dboptr)

        completed_list += sub_result[0]
        failed_list += sub_result[1]

    # 获取本级列表
    dboptr[1].execute(
        "SELECT `id` FROM path_structures WHERE `parent_id` = ?", (dir_id,)
    )
    query_result = dboptr[1].fetchall()

    for i in query_result:
        if not instance.verifyUserAccess(i[0], "recover", user):
            failed_list.append(i[0])
        else:
            # 恢复该目录的直系子级文件和目录
            dboptr[1].execute(
                "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
                (json.dumps(new_state), i[0]),
            )
            completed_list.append(i[0])

    # 无论是否全部恢复成功都恢复此目录
    dboptr[1].execute(
        "UPDATE path_structures SET `state` = ? WHERE `id` = ?;",
        (json.dumps(new_state), dir_id),
    )
    completed_list.append(dir_id)

    dboptr[0].commit()

    return completed_list, failed_list