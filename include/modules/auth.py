from include.bulitin_class.policies import Policies
from include.bulitin_class.users import Users

from include.database.operator import DatabaseOperator

import time
import json

from include.util.convert import convertFile2PathID
from include.util.filetasks import createFileTask


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
                (avatar_file_id,), user.username
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
                    (default_avatar_id,), user.username
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