import json
import socket
import socketserver
from abc import abstractmethod
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from include.experimental.server import ThreadedSocketServer


class NoEndFlagError(Exception): ...


class BaseServerHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server: ThreadedSocketServer):
        self.request: socket.socket = request
        self.client_address = client_address
        self.server = server

        self.config = self.server.config  # alias

        # 该变量用于存储上次发包截断的下一个包的部分
        self._tcp_last_remain: bytes = b""

        # 加密传输启用标志
        self.encrypted_connection = False
        self.aes_key: bytes = None

        self.trace_id: str = None

        from include.logtool import getCustomLogger

        self.logger = getCustomLogger(
            logname=f"main.connHandler.{client_address}",
            filepath=f"{server.root_abspath}/main.log",
        )

        self.setup()

    def send(self, msg: str | bytes) -> None:
        self.logger.debug(f"raw message to send: {msg}")

        msg_to_send = msg.encode() if type(msg) == str else msg

        if self.encrypted_connection:
            encrypted_data = self.aes_encrypt(
                msg, self.aes_key
            )  # aes_encrypt() 接受文本
            self.request.sendall(encrypted_data + b"\r\n")  # + CRLF
        else:
            self.request.sendall(msg_to_send + b"\r\n")

    def recv(self):

        total_data: bytes = bytes()
        while True:
            # 将收到的数据拼接起来
            data = self.request.recv(self.server.BUFFER_SIZE)
            total_data += data
            if len(data) < self.server.BUFFER_SIZE:
                break

        total_data = self._tcp_last_remain + total_data

        if b"\r\n" not in total_data:
            raise NoEndFlagError("No end flag found to seperate packs")

        received_parts = total_data.split(b"\r\n")
        this_pack_data = received_parts[0]

        if self.encrypted_connection:
            decoded = self.aes_decrypt(this_pack_data, self.aes_key)
        else:
            decoded = this_pack_data.decode()
        self.logger.debug(f"received decoded message: {decoded}")

        # 保存未完的包数据
        # 该函数改动后的可靠性仍待考证。
        self._tcp_last_remain = total_data.lstrip(this_pack_data + b"\r\n")

        return decoded

    def aes_encrypt(self, plain_text: str | bytes, key):
        cipher = AES.new(key, AES.MODE_CBC)  # 使用CBC模式

        encrypted_text = cipher.encrypt(
            pad(
                plain_text.encode() if type(plain_text) == str else plain_text,
                AES.block_size,
            )
        )

        iv = cipher.iv

        return iv + encrypted_text

    def aes_decrypt(self, encrypted_text, key):
        iv = encrypted_text[:16]

        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_text = unpad(cipher.decrypt(encrypted_text[16:]), AES.block_size)

        return decrypted_text.decode()

    @abstractmethod
    def respond(self, code, msg=None, **content): ...

    @abstractmethod
    def _do_handshake(self) -> None: ...

    def setup(self) -> None:
        return super().setup()
