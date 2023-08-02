from abc import ABC, abstractmethod

import sqlite3


class AbstractedDBClass(ABC):
    
    @abstractmethod
    def cursor(self):
        ...

    @abstractmethod
    def close(self):...


class Sqlite3DBClass(AbstractedDBClass):
    def __init__(self, sql_filepath: str):
        self.conn = sqlite3.connect(sql_filepath)

        # 创建连接
        self.cursor = self.conn.cursor


    def cursor(self) -> sqlite3.Cursor:
        return self.conn.cursor()
    
    def close(self):
        return self.conn.close()
    
class MySQLDBClass(AbstractedDBClass):
    def __init__(self):
        pass