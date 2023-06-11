# builtin_class/Users.py

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

    def load(self):
        if not self.ifExists():
            return
        
        prelist = []
        prelist.append(self.username)

        self.db_cursor.execute("SELECT rights, groups from users where username = ?", tuple(prelist))
        result = self.db_cursor.fetchone()
        
        self.rights = set(json.loads(result[0])) # 第一步
        self.groups = set(json.loads(result[1]))

        for per_group in self.groups:
            # print(per_group)
            prelist = []
            prelist.append(per_group)
            self.db_cursor.execute("SELECT rights, enabled from groups where name = ?", tuple(prelist))
            per_result = self.db_cursor.fetchone()
            if per_result[1]:
                for i in json.loads(per_result[0]):
                    self.rights.add(i)

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
        if hash == sha256_obj.hexdigest():
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


    def hasRight(self, right=None):
        if not right: # 若未给定权限名，则返回为真
            return True
        if right in self.rights:
            return True
        else:
            return False

    def hasRights(self, rights=[]):
        if not rights: # 若未给定权限名，则返回为真
            return True
        for i in rights:
            if not i in self.rights:
                return False
        return True

if __name__ == "__main__":
    maindb = sqlite3.connect(f"B:\crp9472_personal\cfms_2/general.db")
    user_admin = Users("admin", maindb)
    print(user_admin.ifExists())
    print(user_admin.ifMatchPassword("00aa"))
    can_do = ("all", "generate")
    token = user_admin.generateUserToken(can_do, 3600 , "secret")
    print(token)
    user_admin.load()
    print(user_admin.rights)
    print(user_admin.groups)