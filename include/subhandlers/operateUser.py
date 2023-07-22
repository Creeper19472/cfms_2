import sys, os
import sqlite3

from include.connThread import ConnHandler

class subhandle_OperateUser(ConnHandler):
    def __init__(self, db_conn: sqlite3.Connection):
        self.db_conn = db_conn

    def a():
        pass