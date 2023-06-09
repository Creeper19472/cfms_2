# builtin_class/Users.py

import sqlite3
import hashlib

class Users(object):
    def __init__(self, username, db_conn: sqlite3.Connection, **kwargs):
        self.username = username
        self.db_conn = db_conn
        self.db_cursor = db_conn.cursor()
        self.rights = set()

    def load(self):
        pass

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