# engine.py

import sqlite3

class DB_Sqlite3(object):
    def __init__(self, filename):
        try:
            self.conn = sqlite3.connect(filename)
        except Exception as e:
            e.add_note("在打开数据库连接时出现了问题。")
            raise
        self.cursor = self.conn.cursor()
        
    def execWithCommit(self, execute):
        self.cursor.execute(execute)
        self.conn.commit()
        