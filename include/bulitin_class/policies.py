import sqlite3
import json
from jsonschema import validate # TODO #8

class Policies(object):
    def __init__(self, policy_id, sql_object: sqlite3.Connection):
        self.policy_id = policy_id

        # load policy, not refreshable

        self.conn = sql_object
        self.cursor = self.conn.cursor()

        self.cursor.execute("SELECT content, access_rules, external_access FROM policies WHERE id = ?", (self.policy_id,))

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
    
    def save(self):
        self.cursor.execute("UPDATE policies SET content = ?, access_rules = ?, external_access = ? WHERE ID = ?;", \
                            (self.policy_id, self.access_rules, self.external_access))
        return
