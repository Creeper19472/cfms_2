import hashlib
import secrets
import string
from Crypto.PublicKey import RSA
import sqlite3
from include.bulitin_class.policies import Policies
from include.bulitin_class.users import Users

from include.database.operator import DatabaseOperator

import time
import json

from include.util.convert import convertFile2PathID
from include.util.filetasks import createFileTask
from include.util.structurecheck import StructureValidater


def handle_logout(instance):
    pass

def handle_refreshToken(instance, loaded_recv):
    old_token = loaded_recv["auth"]["token"]
    req_username = loaded_recv["auth"]["username"]

    with DatabaseOperator(instance._pool) as couple:

        user = Users(req_username, *couple)  # 初始化用户对象
        # 读取 token_secret
        with open(f"{instance.server.root_abspath}/content/auth/token_secret", "r") as ts_file:
            token_secret = ts_file.read()

        if new_token := user.refreshUserToken(
            old_token, token_secret, vaild_time=3600
        ):  # return: {token} , False
            instance.respond(0, **{"msg": "ok", "token": new_token})
        else:
            instance.respond(401, msg="invaild token or username")

def handle_getAvatar(instance, loaded_recv, user: Users):
    if not (avatar_username := loaded_recv["data"].get("username")):
        instance.respond(**{"code": -1, "msg": "needs a username"})
        return
    
    with DatabaseOperator(instance._pool) as dboptr: 
        get_avatar_user = Users(avatar_username, *dboptr)

        if not get_avatar_user.ifExists():
            instance.logger.debug(
                f"用户 {user.username} 试图请求帐户 {avatar_username} 的头像，但这个用户并不存在。"
            )
            instance.respond(**{"code": 404, "msg": "not found"})
            return
        

        avatar_policy = Policies("avatars", *dboptr)

        gau_access_rules = get_avatar_user["publicity"].get("access_rules", {})
        gau_external_access = get_avatar_user["publicity"].get("external_access", {})

        if get_avatar_user["publicity"].get("restricted", False):
            if (
                (not avatar_policy["allow_access_without_permission"])
                and (
                    not instance._verifyAccess(
                        user, "read", gau_access_rules, gau_external_access
                    )
                )
                and (not user.hasRights(("super_useravatar",)))
            ):
                instance.respond(403, msg="forbidden")
                return

        if avatar_file_id := get_avatar_user["avatar"].get("file_id", None):
            task_id, task_token, t_filenames = createFileTask(
                instance, (avatar_file_id,), user.username
            )

            mapping = {"": avatar_file_id}

            mapped_dict = convertFile2PathID(t_filenames, mapping)

            instance.respond(
                
                **{
                    "code": 0,
                    "msg": "ok",
                    "data": {
                        "task_id": task_id,
                        "task_token": task_token,
                        "t_filename": mapped_dict,
                    },
                }
            
            )
        else:
            if default_avatar_id := avatar_policy["default_avatar"]:
                task_id, task_token, t_filenames, expire_time = createFileTask(
                    instance, (default_avatar_id,), user.username
                )

                mapping = {"": default_avatar_id}

                mapped_dict = convertFile2PathID(t_filenames, mapping)

                instance.logger.debug(
                    f"用户 {user.username} 请求帐户 {avatar_username} 的头像，返回为默认头像。"
                )

                instance.respond(
                
                    **{
                        "code": 0,
                        "msg": "ok",
                        "data": {
                            "task_id": task_id,
                            "task_token": task_token,
                            "t_filename": mapped_dict,
                            "expire_time": expire_time,
                        },
                    }
                
                )
            else:
                instance.logger.debug(
                    f"用户 {user.username} 试图请求帐户 {avatar_username} 的头像，但用户未设置头像，且策略指定的默认头像为空。"
                )
                instance.respond(**{"code": 404, "msg": "not found", "data": {}})

def handle_getUserProperties(instance, loaded_recv, user: Users):
    if "data" not in loaded_recv:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    target_username = loaded_recv["data"].get("username", user.username)

    if not target_username:
        target_username = user.username  # fallback to whoami

    if target_username != user.username:
        if not user.hasRights(("view_others_properties",)):
            instance.respond(**instance.RES_ACCESS_DENIED)
            return

        with DatabaseOperator(instance._pool) as dboptr:
            query_user_object = Users(target_username, *dboptr)
            if not query_user_object.ifExists():
                instance.respond(**instance.RES_NOT_FOUND)
                return

    else:
        query_user_object = user

    response = {
        "rights": list(query_user_object.rights),
        "groups": list(query_user_object.groups),
        "properties": query_user_object.properties,
    }

    instance.respond(**response)
    return

def handle_operateUser(instance, loaded_recv, user: Users):

    if "data" not in loaded_recv:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if not (action := loaded_recv["data"].get("action", None)):
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    username = loaded_recv["data"].get("username", user.username)

    if not username:
        instance.respond(-1, msg="need a username")

    elif username != user.username and action != "get_publickey":
        if not user.hasRights(("edit_other_users",)):
            instance.respond(**instance.RES_ACCESS_DENIED)
            return

    with DatabaseOperator(instance._pool) as dboptr:
        dest_user = Users(username, *dboptr)

        if not dest_user.ifExists():
            instance.respond(404, msg="user not found")
            return

        dest_user.load()

        user_properties = dest_user.properties
        user_state = user_properties["state"]

        if action in [
            "set_nickname",
            "delete",  # done
            "passwd",  # done
            "set_rights",  # done
            "set_groups",  # done
            "set_username",  # done - not allowed
            "set_status",
            "set_publickey",  # done
            "get_publickey",  # done - TODO #13 单设备一公钥
        ]:
            # 因为这里的操作不是路径操作，故只能手动鉴权

            if action == "set_nickname":
                if not user.hasRights(("set_nickname",)):
                    instance.respond(**instance.RES_ACCESS_DENIED)
                    return

                # if user.username != dest_user.username and not user.hasRights(("set_others",)):
                #     pass

                dboptr[1].execute(
                    "UPDATE `users` SET `nickname` = ? WHERE `username` = ?",
                    (dest_user.username,),
                )

                dboptr[0].commit()

                instance.respond(**instance.RES_OK)
                return

            elif action == "delete":
                if not user.hasRights(("delete_user",)):
                    instance.respond(**instance.RES_ACCESS_DENIED)
                    return

                if dest_user.username == user.username:
                    instance.respond(**
                        {"code": -1, "msg": "a user cannot delete itself"}
                    )
                    return

                ft_conn = sqlite3.connect(f"{instance.server.root_abspath}/content/fqueue.db")
                ft_cursor = ft_conn.cursor()

                # 删除任务, 留下已完成的任务供查证
                # 或许可以改变 done 的值来标记文件 - 任务已取消？
                ft_cursor.execute(
                    "DELETE from ft_queue WHERE username = ? AND done = 0;",
                    (dest_user.username,),
                )
                ft_conn.commit()
                ft_conn.close()

                # 删除用户
                dboptr[1].execute(
                    "DELETE from `users` WHERE `username` = ?;", (dest_user.username,)
                )
                dboptr[0].commit()

                instance.respond(**instance.RES_OK)
                return

            elif action == "set_publickey":  # incomplete - does not support device_id
                new_publickey = loaded_recv["data"].get("publickey", None)
                if not new_publickey:
                    instance.respond(**instance.RES_MISSING_ARGUMENT)
                    return

                try:
                    RSA.import_key(new_publickey)
                except (ValueError, IndexError, TypeError):
                    instance.respond(**{"code": -1, "msg": "not a vaild key"})
                    return

                dboptr[1].execute(
                    "UPDATE `users` SET `publickey` = ? WHERE `username` = ?",
                    (new_publickey, dest_user.username),
                )
                dboptr[0].commit()

                instance.respond(**instance.RES_OK)
                return

            elif action == "get_publickey":
                if user.username != dest_user.username:
                    if not user.hasRights(("view_others_publickey",)):
                        instance.respond(**instance.RES_ACCESS_DENIED)
                        return

                if dest_user.publickey:
                    instance.respond(**
                        {
                            "code": 0,
                            "msg": "ok",
                            "data": {"publickey": dest_user.publickey},
                        }
                    )

                else:
                    instance.respond(**
                        {"code": 404, "msg": "the user does not have a publickey"}
                    )

            elif action == "passwd":
                new_pwd = loaded_recv["data"].get("new_pwd", None)
                if not new_pwd:
                    instance.respond(**instance.RES_MISSING_ARGUMENT)
                    return

                # 随机生成8位salt
                alphabet = string.ascii_letters + string.digits
                salt = "".join(secrets.choice(alphabet) for i in range(8))  # 安全化

                __first = hashlib.sha256(new_pwd.encode()).hexdigest()
                __second_obj = hashlib.sha256()
                __second_obj.update((__first + salt).encode())

                salted_pwd = __second_obj.hexdigest()

                dboptr[1].execute(
                    "UPDATE `users` SET `hash` = ?, `salt` = ? WHERE `username` = ?",
                    (salted_pwd, salt, dest_user.username),
                )

                dboptr[0].commit()

                instance.respond(**instance.RES_OK)

            elif action == "set_username":
                instance.respond(**{"code": -1, "msg": "not allowed"})
                return

            elif action == "set_groups":
                if not user.hasRights(("set_usergroups",)):
                    instance.respond(**instance.RES_ACCESS_DENIED)
                    return

                new_groups = loaded_recv["data"].get("new_groups", None)

                if new_groups == None:
                    instance.respond(**instance.RES_MISSING_ARGUMENT)
                    return

                if not StructureValidater.checkGroupStructure(new_groups)[0]:
                    instance.respond(**
                        {"code": -1, "msg": "invaild data structure"}
                    )
                    return

                dboptr[1].execute(
                    "UPDATE `users` SET `groups` = ? WHERE `username` = ?",
                    (json.dumps(new_groups), dest_user.username),
                )

                instance.respond(**instance.RES_OK)

            elif action == "set_rights":
                if not user.hasRights(("set_userrights",)):
                    instance.respond(**instance.RES_ACCESS_DENIED)
                    return

                new_rights = loaded_recv["data"].get("new_rights", None)

                if new_rights == None:
                    instance.respond(**instance.RES_MISSING_ARGUMENT)
                    return

                if not StructureValidater.checkRightStructure(new_rights)[0]:
                    instance.respond(**
                        {"code": -1, "msg": "invaild data structure"}
                    )
                    return

                dboptr[1].execute(
                    "UPDATE `users` SET `rights` = ? WHERE `username` = ?",
                    (json.dumps(new_rights), dest_user.username),
                )

                instance.respond(**instance.RES_OK)

        else:
            instance.respond(**instance.RES_BAD_REQUEST)