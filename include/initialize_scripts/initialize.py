"""
initialize.py

初始化系统（主要是数据表结构）的专门程序。

定义了一些函数来有条理地处理
"""

import hashlib
from include.bulitin_class.users import AllUsers

from include.database.operator import DatabaseOperator, getDBPool
from include.util.usertools import createUser


def initDatabaseStructure(db_pool):
    """
    这一函数处理数据库初始化的相关步骤。
    它将创建必要的数据表并向其中插入初始数据。
    """

    ### 创建用户组数据表: users
    # 计划中的表栏目： user_id AUTOINCREMENT, username, [password, salt], nickname, status, last_login, created_time
    # 其中 status 有以下几种状态： 0 - OK, 1 - disabled (Are we really going to use this column?)

    dboptr = DatabaseOperator(db_pool)

    dboptr[1].execute(
        "CREATE TABLE users (`user_id` BIGINT PRIMARY KEY AUTO_INCREMENT, `username` varchar(255), \
            `password` TEXT, `salt` TEXT, `nickname` varchar(255), \
            `status` INTEGER, `last_login` INT, `created_time` INT);"
    )

    ### user_permissions
    # columns: user_id, perm_name, perm_type, mode, expire_time

    dboptr[1].execute(
        "CREATE TABLE user_permissions (`user_id` BIGINT PRIMARY KEY, `perm_name` varchar(255), \
            `perm_type` varchar(64), `mode` varchar(64), `expire_time` INT);"
    )

    createUser("admin", "123456", user_groups={"sysop": -1}, all_users=AllUsers(db_pool))


    
