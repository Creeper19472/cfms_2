from typing import Any
from mysql.connector.pooling import MySQLConnectionPool

from collections import UserList

def getDBPool(config):

    mysql_host = config["database"]["mysql_host"]
    mysql_port = config["database"]["mysql_port"]

    mysql_username = config["database"]["mysql_username"]
    mysql_password = config["database"]["mysql_password"]

    # 检查连接池设置是否存在问题
    if (config_pmc:=config["database"]["pool_max_connections"]) <= 0 or config_pmc > 32:
        raise ValueError("Max pool connections out of range")
    # 指定使用的数据库
    mysql_db_name = config["database"]["mysql_db_name"]

    # 创建连接池
    _pool = MySQLConnectionPool(
        host=mysql_host,     # 数据库主机地址
        user=mysql_username,      # 数据库用户名
        passwd=mysql_password,        # 数据库密码
        port=mysql_port,
        database=mysql_db_name,
        pool_size = config_pmc
    )

    return _pool

class DatabaseOperator(UserList):
    def __init__(self, pool: MySQLConnectionPool):

        self._closed = False

        self._pool = pool
        
        self._current_connection = self._pool.get_connection()
        self._current_cursor = self._current_connection._cnx.cursor(prepared=True)

        self.data = [self._current_connection, self._current_cursor]

    # def __getitem__(self, key):
    #     if key == 0:
    #         return self._current_connection
    #     elif key == 1:
    #         return self._current_cursor
    #     else:
    #         raise ValueError
        
    def __del__(self):
        self.close()

    # def __list__(self):
    #     return (self._current_connection, self._current_cursor)

    def __enter__(self):
        return self._current_connection, self._current_cursor
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return
    
    def close(self):
        if not self._closed:
            self._current_cursor.close()
            self._current_connection.close()

            self._closed = True
        return