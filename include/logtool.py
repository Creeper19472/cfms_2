import logging
from logging.handlers import RotatingFileHandler

"""
logtool.py

此处存放用于统一日志记录功能的函数。
可能存在尚待完善的部分。
"""

class LogClass(object): # 已弃用
    def __init__(
        self, logname, level=(logging.DEBUG, logging.INFO), filepath="default.log"
    ):
        # logname 是定义的日志对象的名称。
        self.logger = logging.getLogger(logname)
        self.logger.setLevel(level=logging.DEBUG)  # This level must be 'logging.DEBUG'.
        self.logger.propagate = 0
        self.lfhandler = RotatingFileHandler(filename=filepath, maxBytes=10485760, backupCount=1)
        self.cshandler = logging.StreamHandler()
        formatter1 = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        formatter2 = logging.Formatter("[%(asctime)s %(levelname)s] %(message)s")
        self.lfhandler.setLevel(level[0])
        self.cshandler.setLevel(level[1])
        self.lfhandler.setFormatter(formatter1)
        self.cshandler.setFormatter(formatter2)
        self.logger.addHandler(self.lfhandler)
        self.logger.addHandler(self.cshandler)

        self.__call__ = self.logger

def getCustomLogger(logname, level=(logging.DEBUG, logging.INFO), filepath="default.log"):
    logger = logging.getLogger(logname)
    logger.setLevel(level=logging.DEBUG)  # This level must be 'logging.DEBUG'.
    logger.propagate = 0
    lfhandler = RotatingFileHandler(filename=filepath, maxBytes=10485760, backupCount=1)
    cshandler = logging.StreamHandler()
    formatter1 = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    formatter2 = logging.Formatter("[%(asctime)s %(levelname)s] %(message)s")
    lfhandler.setLevel(level[0])
    cshandler.setLevel(level[1])
    lfhandler.setFormatter(formatter1)
    cshandler.setFormatter(formatter2)
    logger.addHandler(lfhandler)
    logger.addHandler(cshandler)


    return logger