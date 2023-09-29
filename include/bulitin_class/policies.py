import sqlite3
import json
from typing import Union
from jsonschema import validate # TODO #8

from mysql.connector.connection import MySQLConnection
from mysql.connector.cursor import MySQLCursorPrepared

class Policies(object):
    def __init__(self, policy_id, db_conn: Union[sqlite3.Connection, MySQLConnection], \
                 db_cursor: Union[sqlite3.Cursor, MySQLCursorPrepared]) -> None:
        self.policy_id = policy_id

        # load policy, not refreshable

        self.conn = db_conn
        self.cursor = db_cursor

        # print(self.cursor._connection)

        self.cursor.execute("SELECT `content`, `access_rules`, `external_access` FROM `policies` WHERE `id` = ?", (self.policy_id,))

        # 检查是否有重名
        fetched = self.cursor.fetchall()
        if len(fetched) < 1:
            raise ValueError(f"the policy '{self.policy_id}' does not exist")
        elif len(fetched) > 1:
            raise RuntimeError(f"'{self.policy_id}' has more than one entry in database")
        
        decomposed = fetched[0]

        self.content = json.loads(decomposed[0])
        self.access_rules = json.loads(decomposed[1])
        self.external_access = json.loads(decomposed[2])

    def __getitem__(self, key):
        return self.content[key]
    
    def __setitem__(self, key, value):
        self.content[key] = value
    
    def __contains__(self, item):
        return item in self.content
    
    def save(self) -> None:
        self.cursor.execute("UPDATE policies SET `content` = ?, `access_rules` = ?, `external_access` = ? WHERE `id` = ?;", \
                            (self.policy_id, self.access_rules, self.external_access))
        self.conn.commit()
        return
