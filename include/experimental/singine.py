# Singleton Database Engine
# singine.py

# 提供实验性的单例模式的用以支持 ORM 架构的模块。

from sqlalchemy import create_engine
import tomllib, sys, os

if __name__ == "__main__":
    sys.exit()

config: dict = {}

if os.path.exists("./config.toml"):
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)
else:
    raise FileNotFoundError("config.toml not found. ensure you're in the working directory?")

_mysql_host = config["database"]["mysql_host"]
_mysql_port = config["database"]["mysql_port"]

_mysql_username = config["database"]["mysql_username"]
_mysql_password = config["database"]["mysql_password"]

_db_name = config["database"]["mysql_db_name"]

# TODO - 加入对多种数据库类型的支持，这需要对之前代码的大幅度改动
engine = create_engine(
    f"mysql+mysqldb://{_mysql_username}:{_mysql_password}@{_mysql_host}:{_mysql_port}/{_db_name}", pool_recycle=3600, echo=True)

from sqlalchemy.orm import sessionmaker
Session = sessionmaker(bind=engine)