import json
from include.bulitin_class.policies import Policies

from include.bulitin_class.users import Users
from include.database.operator import DatabaseOperator


def handle_createGroup(instance, loaded_recv, user: Users):
    if "data" not in loaded_recv:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    new_group_name = loaded_recv["data"].get("group_name", None)
    new_group_members = loaded_recv["data"].get("group_members", None)
    new_group_enabled = loaded_recv["data"].get("enabled", None)

    if new_group_name:
        if len(new_group_name) > 32:
            instance.respond(**{"code": -1, "msg": "group name too long"})
            return
    else:
        instance.respond(**instance.RES_MISSING_ARGUMENT)
        return

    if not user.hasRights(("create_group",)):
        instance.respond(**instance.RES_ACCESS_DENIED)
        return

    with DatabaseOperator(instance._pool) as dboptr:

        # 判断组是否存在
        dboptr[1].execute(
            "SELECT count(`name`) from `groups` where `name` = ?", (new_group_name,)
        )
        result = dboptr[1].fetchone()

        if result[0] != 0:  # 不做过多判断（虽然本该如此）
            instance.respond(**{"code": -1, "msg": "group exists"})
            return

        new_group_rights = loaded_recv["data"].get("rights", None)

        group_policy = Policies("group_settings", *dboptr)

        if new_group_rights != None or new_group_enabled != None:  # 不为未提供的，因提供空列表也是一种提交
            if not user.hasRights(("custom_new_group_settings",)):
                instance.respond(**instance.RES_ACCESS_DENIED)
                return

        if new_group_members != None:
            if not user.hasRights(("custom_new_group_members",)):
                instance.respond(**instance.RES_ACCESS_DENIED)
                return

        if new_group_rights == None:  # fallback
            new_group_rights = group_policy["default_rights"]

        if new_group_members == None:
            new_group_members = group_policy["default_members"]

        if new_group_enabled == None:
            new_group_enabled = group_policy["default_enabled"]
        elif new_group_enabled != 0 and new_group_enabled != 1:
            instance.respond(**{"code": 400, "msg": "group_enabled is invaild"})
            return

        # 开始处理

        errors = []

        dboptr[1].execute(
            "INSERT INTO `groups` (`name`, `enabled`, `rights`, `properties`) VALUES(?, ?, ?, ?)",  # 插入新的组
            (
                new_group_name,
                new_group_enabled,
                json.dumps(new_group_rights),
                json.dumps({}),
            ),
        )

        for i in new_group_members:
            dboptr[1].execute(
                "SELECT `groups` FROM `users` WHERE `username` = ?", (i,)
            )
            query_result = dboptr[1].fetchone()
            if not query_result:
                errors.append((i, "NOT_FOUND"))
                continue
            old_groups = json.loads(query_result[0])

            new_groups = old_groups  # copy
            new_groups[new_group_name] = {"expire": 0}

            dboptr[1].execute(
                "UPDATE `users` SET `groups` = ? WHERE `username` = ? ",
                (json.dumps(new_groups), i),
            )

        dboptr[0].commit()

    instance.respond(**instance.RES_OK)

    return