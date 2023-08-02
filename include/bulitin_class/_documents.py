import sys, os, sqlite3
import json

class Documents:
    def __init__(self, document_id, db_conn: sqlite3.Connection):
        self.document_id = document_id
        self.db_conn = db_conn

        self.if_exists = False

        self.filename = None
        self.abspath = None
        self.owner = None
        self.needed_rights = []
        self.metadata = {}

    def load(self):
        cursor = self.db_conn.cursor()
        doc_id_tuple = (str(self.document_id))
        cursor.execute("SELECT filename, abspath, owner, needed_rights, metadata from document_indexes where id = ?", doc_id_tuple)
        result = cursor.fetchone()
        if result:
            self.filename, self.abspath, self.owner = result[0:3]
            self.needed_rights = json.loads(result[3])
            self.metadata = json.loads(result[4])
            self.if_exists = True
        else:
            return False
    
    def hasUserMetRequirements(self, user: object):
        pass

if __name__ == "__main__":
    maindb = sqlite3.connect(f"B:\crp9472_personal\cfms_2/general.db")
    doc = Documents(0, maindb)
    doc.load()
    print(doc.owner, doc.needed_rights)