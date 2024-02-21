# builtin_class/Users.py

import secrets
import hashlib
import jwt
import time

from include.database.operator import DatabaseOperator


class AllUsers:
    def __init__(self, db_pool):
        self._db_pool = db_pool

    def __getitem__(self, username):
        if username in self:
            return Users(username, self._db_pool)
        else:
            raise KeyError("No such user")

    def __contains__(self, username):
        with DatabaseOperator(self._db_pool) as dboptr:
            dboptr[1].execute(
                "SELECT count(`username`) FROM `users` WHERE `username` = ?",
                (username,),
            )
            _result = dboptr[1].fetchone()
        del dboptr  # 清理

        return bool(_result[0])


class Users:
    def __init__(self, username: str, db_pool):
        self._db_pool = db_pool

        with DatabaseOperator(self._db_pool) as dboptr:
            dboptr[1].execute(
                "SELECT `user_id`, `password`, `salt`, `nickname`, `status`, \
                    `last_login`, `created_time` FROM `users` WHERE `username` = ?",
                (username,),
            )

            _result = dboptr[1].fetchone()  # 不考虑多个结果的情况

            (
                self.user_id,
                self.password,
                self.pwd_salt,
                self.nickname,
                self.status,
                self.last_login,
                self.created_time,
            ) = _result

            self.username = username

            # 载入权限和用户组
            dboptr[1].execute(
                "SELECT `perm_name`, `perm_type`, `mode` FROM `user_permissions` WHERE `user_id` = ? AND (`expire_time` > ? OR `expire_time` <= 0)",
                (self.user_id, time.time()),
            )
            _perms = dboptr[1].fetchall()

            self.rights = set()
            self.groups = set()

            _revoked_rights = set()

            for each_perm in _perms:
                if each_perm[1] == "right":
                    if each_perm[2] == "granted":
                        self.rights.add(each_perm[0])
                    elif each_perm[2] == "revoked":
                        _revoked_rights.add(each_perm[0])
                    else:
                        raise RuntimeError(
                            f"Invaild mode for right {each_perm[0]}: {each_perm[2]}"
                        )
                elif each_perm[1] == "group":
                    if each_perm[2] == "granted":
                        self.groups.add(each_perm[0])
                    else:
                        raise RuntimeError(
                            f"Invaild mode for group {each_perm[0]}: {each_perm[2]}"
                        )
                else:
                    raise RuntimeError(f"Invaild permission type: {each_perm[1]}")
                
            # 默认包含 user 组
            self.groups.add("user")

            # 载入用户组所包含的权限
                
            for i in self.groups:

                dboptr[1].execute(
                    "Select `right`, `mode` from group_rights left join `groups` ON (`groups`.`id` = `group_rights`.`id`) AND (`groups`.`g_id` = ?) AND (`expire_time` > ? OR `expire_time` <= 0) AND `groups`.`status` = 0;",
                    (i, time.time()),
                )
                _rights = dboptr[1].fetchall()

                _group_revoked_rights = set()

                for each_right in _rights:
                    if each_right[1] == "granted":
                        self.rights.add(each_perm[0])
                    elif each_right[1] == "revoked":
                        _group_revoked_rights.add(each_perm[0])
                    else:
                        raise RuntimeError(
                            f"Invaild mode for right {each_perm[0]} of group {i}: {each_perm[1]}"
                        )

            self.rights -= _revoked_rights
            self.rights -= _group_revoked_rights
            

            # 载入 metadata - TODO

    def getMetadata(self, key: str) -> str:
        with DatabaseOperator(self._db_pool) as dboptr:
            dboptr[1].execute(
                "SELECT `value` FROM `user_metadata` WHERE `user_id` = ? AND `key` = ?",
                (self.user_id, key),
            )
            _result = dboptr[1].fetchone()

        if not _result:
            raise KeyError("No such key")
        else:
            return _result[0]

    def isMatchPassword(self, pwd_to_compare):
        sha256_obj = hashlib.sha256()
        sha256_obj.update((pwd_to_compare + self.pwd_salt).encode())

        return secrets.compare_digest(self.password, sha256_obj.hexdigest())

    def generateUserToken(self, can_be_used: tuple, vaild_time: int, secret):
        now_time = int(time.time())
        expire_time = now_time + vaild_time
        payload = {
            "exp": expire_time,
            "nbf": now_time,
            "sub": self.username,
            "can_be_used": can_be_used,
        }
        encoded = jwt.encode(payload, secret, algorithm="HS256")

        with DatabaseOperator(self._db_pool) as dboptr:
            dboptr[1].execute(
                "UPDATE `users` SET `last_login` = ? WHERE `user_id` = ?",
                (now_time, self.user_id),
            )
            dboptr[0].commit()

        return encoded

    def refreshUserToken(self, old_token, secret, vaild_time=3600):
        if self.isVaildToken(old_token, secret, leeway=60):
            return self.generateUserToken(
                ("all"), vaild_time, secret
            )  # todo: 传入 can_be_used
        else:
            return False

    def isVaildToken(self, given_token, secret, leeway=0):  # 针对于这个用户而言的
        try:
            decoded = jwt.decode(
                given_token,
                secret,
                leeway=leeway,
                algorithms=["HS256"],
                options={"require": ["exp", "sub"]},
            )
        except jwt.ExpiredSignatureError:
            return False
        except:  # fallback
            return False

        return decoded["sub"] == self.username

    def ifMatchRequirements(self, rules: list):

        def matchRights(sub_rights_group):
            if not sub_rights_group:
                return True

            sub_match_mode = sub_rights_group.get("match", "all")
            sub_rights_require = sub_rights_group.get("require", [])

            if not sub_rights_require:
                return True

            if sub_match_mode == "all":
                return set(sub_rights_require) <= self.rights

            elif sub_match_mode == "any":

                for right in sub_rights_require:
                    if right in self.rights:
                        return True
                return False  # fallback

            else:
                raise

        def matchGroups(sub_groups_group):
            if not sub_groups_group:
                return True  # if no content, return True

            sub_match_mode = sub_groups_group.get("match", "all")
            sub_groups_require = sub_groups_group.get("require", [])

            if not sub_groups_require:
                return True

            if sub_match_mode == "all":
                return set(sub_groups_require) <= self.groups

            elif sub_match_mode == "any":
                for group in sub_groups_require:
                    if group in self.groups:
                        return True

                return False  # fallback
            else:
                raise

        def matchSubGroup(sub_group):  # TODO #6 fix

            sub_match_mode = sub_group.get("match", "all")

            sub_rights_group = sub_group.get("rights", {})
            sub_groups_group = sub_group.get("groups", {})

            if not (sub_rights_group.get("require", [])) or (
                not sub_groups_group.get("require", [])
            ):
                sub_match_mode = "all"

            if sub_match_mode == "any":

                if matchRights(sub_rights_group) or matchGroups(sub_groups_group):
                    return True
                else:
                    return False
            if sub_match_mode == "all":
                if matchRights(sub_rights_group) and matchGroups(sub_groups_group):
                    return True
                else:
                    return False
            else:
                raise ValueError(r'the value of "match" must be "all" or "any"')

        def matchPrimarySubGroup(per_match_group):
            match_mode = per_match_group.get("match", "all")  # fallback: all
            for sub_group in per_match_group["match_groups"]:
                if not sub_group:
                    continue

                state = matchSubGroup(sub_group)

                if match_mode == "any":
                    if state:
                        return True
                elif match_mode == "all":
                    if not state:
                        return False
                    # TODO

            if match_mode == "any":
                return False
            elif match_mode == "all":
                return True

        if not rules:
            return True

        for per_match_group in rules:
            if not per_match_group:  # quick judgement
                continue  # for case {}

            if not matchPrimarySubGroup(per_match_group):
                return False

        return True

    ifMatchRules = ifMatchRequirements
