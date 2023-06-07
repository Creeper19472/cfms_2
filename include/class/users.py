# class/Users.py

class Users(object):
    def __init__(self, username, **kwargs):
        self.username = username
        self.rights = set()

    def matchPassword(self, given):
        pass

    def hasRight(self, right=None):
        if not right: # 若未给定权限名，则返回为真
            return True
        if right in self.rights:
            return True
        else:
            return False

    def hasRights(self, rights=[]):
        if not rights: # 若未给定权限名，则返回为真
            return True
        for i in rights:
            if not i in self.rights:
                return False
        return True

