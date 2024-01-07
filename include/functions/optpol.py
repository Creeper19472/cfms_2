import json
from include.bulitin_class.users import Users
from include.database.operator import DatabaseOperator


def handle_getPolicy(instance, loaded_recv, user: Users):
    req_policy_id = loaded_recv["data"]["policy_id"]

    action = "read"  # "getPolicy"，所以目前 action 就是 read

    with DatabaseOperator(instance._pool) as dboptr:
        dboptr[1].execute(
            "SELECT `content`, `access_rules`, `external_access` FROM `policies` WHERE `id` = ?",
            (req_policy_id,),
        )

        fetched = dboptr[1].fetchone()
        # 不是很想再写判断是否有重复ID的逻辑，反正出了问题看着办吧，这不是我要考虑的事

        if not fetched:  # does not exist
            instance.respond(
                **{"code": 404, "msg": "the policy you've requested does not exist"}
            )
            return

        content = json.loads(fetched[0])
        access_rules = json.loads(fetched[1])
        external_access = json.loads(fetched[2])

        if not instance._verifyAccess(user, action, access_rules, external_access):
            instance.respond(**{"code": 403, "msg": "forbidden"})
        else:
            instance.respond(**{"code": 0, "data": content})

    return