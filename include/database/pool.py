import dbutils.persistent_db

def getDBPool(config: dict):
    if config["database"]["db_type"] == "sqlite3":
        import sqlite3
        persist_pool = dbutils.persistent_db.PersistentDB(sqlite3, 0, database=config["database"]["sqlite3_db_name"])
        return persist_pool
    elif config["database"]["db_type"] == "mysql":
        from mysql.connector.pooling import MySQLConnectionPool

        mysql_host = config["database"]["mysql_host"]
        mysql_port = config["database"]["mysql_port"]

        mysql_username = config["database"]["mysql_username"]
        mysql_password = config["database"]["mysql_password"]

        # 检查连接池设置是否存在问题
        if (config_pmc:=config["database"]["pool_max_connections"]) <= 0 or config_pmc > 32:
            raise ValueError("Max pool connections out of range")
        # 指定使用的数据库
        mysql_db_name = config["database"]["mysql_db_name"]

        # 第一步，创建连接
        mysql_pool = MySQLConnectionPool(
            host=mysql_host,     # 数据库主机地址
            user=mysql_username,      # 数据库用户名
            passwd=mysql_password,        # 数据库密码
            port=mysql_port,
            database=mysql_db_name,
            pool_size = config_pmc,
            
        )

        return mysql_pool
    
    else:
        raise TypeError("Unsupported database type")