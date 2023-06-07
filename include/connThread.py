# connThread.py
import threading

class ConnThreads(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.thread_name = args[0]
