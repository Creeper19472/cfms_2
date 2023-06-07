import logging

"""
logtool.py

此处存放用于统一日志记录功能的函数。
可能存在尚待完善的部分。
"""

class log(object):
    def __init__(
        self, logname, level=(logging.DEBUG, logging.INFO), filepath="default.log"
    ):
        # logname 是定义的日志对象的名称。
        self.logger = logging.getLogger(logname)
        self.logger.setLevel(level=logging.DEBUG)  # This level must be 'logging.DEBUG'.
        self.logger.propagate = 0
        self.lfhandler = logging.FileHandler(filename=filepath)
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
