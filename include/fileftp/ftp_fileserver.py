from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import MultiprocessFTPServer  # <-

import os
import sys
import hashlib

from pyftpdlib.handlers import FTPHandler

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed


class DummyMD5Authorizer(DummyAuthorizer):

    def validate_authentication(self, username, password, handler):
        sha256_obj = hashlib.sha256()
        sha256_obj.update((password+salt).encode())
        if hash == sha256_obj.hexdigest():
            return True
        else:
            return False

        if sys.version_info >= (3, 0):
            password = sha256(password.encode('utf-8'))
        hash = sha256(password).hexdigest()
        try:
            if self.user_table[username]['pwd'] != hash:
                raise KeyError
        except KeyError:
            raise AuthenticationFailed



def main():
    authorizer = DummyAuthorizer()
    authorizer.add_user('user', '12345', '.')
    handler = FTPHandler
    handler.authorizer = authorizer
    server = MultiprocessFTPServer(('', 2121), handler)
    server.serve_forever()

if __name__ == "__main__":
    main() #TODO