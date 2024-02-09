"""
usertools.py

This file defines quite a few of user functions.
Used to function without a user instance.
"""


import hashlib
import secrets
import string
import time
from include.bulitin_class.users import AllUsers, Users
from include.database.operator import DatabaseOperator

class ExistingUserError(Exception):...
class UserNotFoundError(Exception):...

# class InvaildLengthError(Exception):...

# class UsernameTooLongError(InvaildLengthError):...
# class NicknameTooLongError(InvaildLengthError):...

def getPasswdSHA256(passwd: str, salt: str):
    """
    该函数生成一个与给定密码和盐值相对应的SHA256字符串。
    使用于初始化用户密码的过程中。
    """
    raw_pwd_sha256 = hashlib.sha256(passwd.encode()).hexdigest()

    second_obj = hashlib.sha256()  # 实例化新的对象然后进行运算
    second_obj.update((raw_pwd_sha256 + salt).encode())
    return second_obj.hexdigest()

def createUser(username: str, password: str, nickname=None, 
               user_granted_rights: dict = {}, user_revoked_rights: dict = {},
               user_groups: dict = {},
               status: int = 0,
               all_users: AllUsers = None):
    
    """
    在这里我们规定了 user_granted_rights 及其类似参数的格式：

    user_granted_rights = {
        "xxx": 1145141919810.0,
        ...
    }

    这样的字典以权限/用户组的名称为键，以其过期时间为键值。

    （我想我们或许不会再向其中加入其他设置了吧...如果真是那样，麻烦就大了）

    """

    if not all_users:
        raise NotImplementedError("Cannot function without all_users given at this time")

    if not nickname:
        nickname = username

    if len(username) > 32:  # max 255
        raise ValueError("username too long")
    if len(nickname) > 64:
        raise ValueError("user nickname too long")
        
    # 判断用户是否存在
    if username in all_users:
        raise RuntimeError("user exists")

    # 随机生成8位salt
    alphabet = string.ascii_letters + string.digits
    salt = "".join(secrets.choice(alphabet) for i in range(8))  # 安全化

    salted_pwd = getPasswdSHA256(password, salt)

    insert_user = (
        username,
        salted_pwd,
        salt,
        nickname,
        status,
        0, # last_login
        created_time:=time.time()
    )

    with DatabaseOperator(all_users._db_pool) as dboptr:

        dboptr[1].execute(
            "INSERT INTO `users` (`username`, `password`, `salt`, `nickname`, `status`, `last_login`, \
                `created_time`) VALUES(?, ?, ?, ?, ?, ?, ?)", insert_user
        )

        user_row_id = dboptr[1].lastrowid

        # 第二步，逐条插入权限设定

        insert_perms = []

        for perm_name in user_granted_rights:
            insert_perms.append((user_row_id, perm_name, "right", "granted", user_granted_rights[perm_name]))

        for perm_name in user_revoked_rights:
            insert_perms.append((user_row_id, perm_name, "right", "revoked", user_revoked_rights[perm_name]))

        for perm_name in user_groups:
            insert_perms.append((user_row_id, perm_name, "group", "granted", user_groups[perm_name]))
                                
        dboptr[1].executemany(
            "INSERT INTO `user_permissions` (`user_id`, `perm_name`, `perm_type`, `mode`, `expire_time`) \
                VALUES(?, ?, ?, ?, ?)", insert_perms
        )

        dboptr[0].commit() # 在这里提交，意味着给定的 dboptr 最好是“干净”的

    return