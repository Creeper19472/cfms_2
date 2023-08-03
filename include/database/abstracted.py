from abc import ABC, abstractmethod

import sqlite3
from typing import Any, Optional, Type
import mysql.connector
from mysql.connector.cursor import MySQLCursor

class AbstractedConnection(ABC):
    pass


AbstractedConnection.register(sqlite3.Connection)
AbstractedConnection.register(mysql.connector.connection.MySQLConnection)


class CustomizedMySQLConnection(mysql.connector.connection.MySQLConnection, AbstractedConnection):
    def __init__(self, prepared=True, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._prepared = prepared

    def cursor(
        self,
        buffered: bool | None = None,
        raw: bool | None = None,
        prepared: bool | None = None,
        cursor_class: type[MySQLCursor] | None = None,
        dictionary: bool | None = None,
        named_tuple: bool | None = None,
    ) -> MySQLCursor:
        
        prepared = prepared if prepared is not None else self._prepared

        return super().cursor(
            buffered, raw, prepared, cursor_class, dictionary, named_tuple
        )
    


class AbstractedCursor(ABC):
    pass


AbstractedCursor.register(sqlite3.Cursor)


class WrappedMySQLConnection():
    def __init__(self, conn: mysql.connector.MySQLConnection, **kwargs):
        self._conn = conn
        self._prepared = kwargs.get("prepared", True)

    def cursor(self, prepared=None, **kwargs):
        prepared = prepared if prepared is not None else self._prepared

        if "prepared" in kwargs.keys():
            del kwargs["prepared"]

        return self._conn.cursor(prepared=prepared, **kwargs)
    
    def close(self):
        return self._conn.close()
    
    def commit(self):
        return self._conn.commit()
    
    @property
    def total_changes(self):
        return -1 # 不可用



def getDBConnection(config):
    db_config = config["database"]

    use_db_type = db_config["db_type"]

    if use_db_type == "sqlite3":
        sqlite3_db_name = db_config["sqlite3_db_name"]

        return sqlite3.connect(sqlite3_db_name)

    elif use_db_type == "mysql":
        host, port = db_config["mysql_host"], db_config["mysql_port"]
        username, passwd = db_config["mysql_username"], db_config["mysql_password"]

        db_name = db_config["mysql_db_name"]

        db = mysql.connector.connect(
            host=host,
            port=port,
            user=username,
            password=passwd,
            database=db_name,
            charset="utf8mb4",
        )


        return WrappedMySQLConnection(db)
