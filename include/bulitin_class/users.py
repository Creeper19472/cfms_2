# builtin_class/Users.py

import secrets
import sqlite3
import hashlib
import jwt
import time
import json

class Users(object):
    def __init__(self, username, db_conn: sqlite3.Connection, **kwargs):
        self.username = username
        self.db_conn = db_conn
        self.db_cursor = db_conn.cursor()
        self.rights = set()
        self.groups = set()
        self.properties = {}

        self.load() # by default, in order to avoid mistakes

    def __getitem__(self, key):
        return self.properties[key]
    
    def __setitem__(self, key, value):
        self.properties[key] = value
    
    def __contains__(self, item):
        return item in self.properties

    def load(self):
        if not self.ifExists():
            return
        
        prelist = []
        prelist.append(self.username)

        self.db_cursor.execute("SELECT rights, groups, properties from users where username = ?", tuple(prelist))
        result = self.db_cursor.fetchone()

        self.rights = set() # 重置
        self.groups = set()

        self.properties = json.loads(result[2])

        for i in (loaded_result := json.loads(result[0])):
            if (not (expire_time:=loaded_result[i].get("expire", 0))) or (expire_time > time.time()):
                if not loaded_result[i].get("revoke", False):
                    self.rights.add(i)
                else:
                    self.rights - {i,} # remove

        for j in (loaded_result := json.loads(result[1])):
             if (not (expire_time:=loaded_result[j].get("expire", 0))) or (expire_time > time.time()):
                self.groups.add(j)
                # 组不支持 revoke，因为无意义

        del loaded_result

        self.groups.add("user") # deafult and forced group

        for per_group in self.groups:
            # print(per_group)
            prelist = []
            prelist.append(per_group)
            self.db_cursor.execute("SELECT rights, enabled from groups where name = ?", tuple(prelist))
            per_result = self.db_cursor.fetchone()
            if per_result[1]:
                for i in (per_group_rights := json.loads(per_result[0])):
                    if (not (expire_time:=per_group_rights[i].get("expire", 0))) or (expire_time > time.time()):
                        if not per_group_rights[i].get("revoke", False):
                            self.rights.add(i)
                        else:
                            self.rights - {i,} # remove

    def ifExists(self):
        # 可能注入的位点
        prelist = []
        prelist.append(self.username)
        self.db_cursor.execute("SELECT count(username) from users where username = ?", tuple(prelist))
        result = self.db_cursor.fetchone()
        if result[0] == 1:
            return True
        elif result[0] > 1:
            raise
        else:
            return False

    def ifMatchPassword(self, given):
        prelist = []
        prelist.append(self.username)
        self.db_cursor.execute("SELECT hash, salt from users where username = ?", tuple(prelist))

        hash, salt = self.db_cursor.fetchone()
        # 初始化sha256对象
        sha256_obj = hashlib.sha256()
        sha256_obj.update((given+salt).encode())
        if secrets.compare_digest(hash, sha256_obj.hexdigest()):
            return True
        else:
            return False
        
    def generateUserToken(self, can_be_used: tuple, vaild_time: int, secret):
        now_time = int(time.time())
        expire_time = now_time + vaild_time
        payload = {
            "exp": expire_time,
            "nbf": now_time,
            "sub": self.username,
            "can_be_used" : can_be_used
            }
        encoded = jwt.encode(payload, secret, algorithm="HS256")
        return encoded
    
    def refreshUserToken(self, old_token, secret, vaild_time = 3600):
        if self.ifVaildToken(old_token, secret, leeway=60):
            return self.generateUserToken(("all"), vaild_time, secret) # todo: 传入 can_be_used
        else:
            return False
        
    def ifVaildToken(self, given_token, secret, leeway=0): # 针对于这个用户而言的
        try:
            decoded = jwt.decode(given_token, secret, leeway=leeway, algorithms=["HS256"], options={"require": ["exp", "sub"]})
        except jwt.ExpiredSignatureError:
            return False
        except: # fallback
            return False
        if decoded["sub"] == self.username:
            if not self.ifExists():
                return False
            return True
        else:
            return False


    def hasRight(self, right=None): # hasRights() is recommended
        if not right: # 若未给定权限名，则返回为真
            return True
        if right in self.rights:
            return True
        else:
            return False

    def hasRights(self, rights=()):
        if not rights: # 若未给定权限名，则返回为真
            return True
        for i in rights:
            if not i in self.rights:
                return False
        return True
    
    def hasGroups(self, groups=()):
        if not groups:
            return True
        for i in groups:
            if not i in self.groups:
                return False
        return True

    def ifMatchRequirements(self, rules: list):

        user = self # alias


        def matchRights(sub_rights_group):
            if not sub_rights_group:
                return True
            
            sub_match_mode = sub_rights_group.get("match", "all")
            sub_rights_require = sub_rights_group.get("require", [])

            if not sub_rights_require:
                return True

            if sub_match_mode == "all":
                return user.hasRights(sub_rights_require)

            elif sub_match_mode == "any":
                
                for right in sub_rights_require:
                    if user.hasRight(right):
                        return True
                return False # fallback
            else:
                raise

        def matchGroups(sub_groups_group):
            if not sub_groups_group:
                return True # if no content, return True

            sub_match_mode = sub_groups_group.get("match", "all")
            sub_groups_require = sub_groups_group.get("require", [])

            if not sub_groups_require:
                return True

            if sub_match_mode == "all":
                return user.hasGroups(sub_groups_require)

            elif sub_match_mode == "any":
                for group in sub_groups_require:

                    if user.hasGroups((group,)):
                        return True
                
                return False # fallback
            else:
                raise


        def matchSubGroup(sub_group): # TODO #6 fix

            sub_match_mode = sub_group.get("match", "all")

            sub_rights_group = sub_group.get("rights", {})
            sub_groups_group = sub_group.get("groups", {})

            if not (sub_rights_group.get("require",[])) or (not sub_groups_group.get("require", [])):
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
            match_mode = per_match_group.get("match", "all") # fallback: all
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
            if not per_match_group: # quick judgement
                continue # for case {}

            if not matchPrimarySubGroup(per_match_group):
                return False
        
        return True
                    
    ifMatchRules = ifMatchRequirements
                    

                    
                


if __name__ == "__main__":
    maindb = sqlite3.connect(f"B:\crp9472_personal\cfms_2/general.db")
    user_admin = Users("admin", maindb)
    print(user_admin.ifExists())
    print(user_admin.ifMatchPassword("00aa"))
    can_do = ("all", "generate")
    token = user_admin.generateUserToken(can_do, 3600 , "secret")
    print(token)
    user_admin.load()
    # print(user_admin.rights)
    # print(user_admin.groups) # users 不显示
    # print(user_admin.hasGroups(["user"]))

    test_rules = [ # 列表，并列满足 与 条件
        {
            "match": "any",
            "match_groups": [ # 下级匹配组，满足 any 条件 => True
                {
                    "match": "any",
                    "rights": {
                        "match": "any",
                        "require": ["read"]
                    },
                    "groups": {
                        "match": "any",
                        "require": ["sysop"]
                    }
                }
            ]
        }, 
        {
            "match": "all",
            "match_groups": [
                {
                    "match": "any",
                    "rights": {
                        "match": "any",
                        "require": ["root", "a"]
                    }
                }
            ]
        }, 
    ]


    # print(user_admin.hasGroups(["user", "sysop", "readers"]))
    print(user_admin.groups)
    print(user_admin.rights)
    print(user_admin.ifMatchRules(test_rules))