from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class ClassRSA:
    def __init__(self, pub, pri):
        self.public_key = RSA.import_key(pub) # object
        self.private_key = RSA.import_key(pri)
        

if __name__ == "__main__":
    data = b"aabbcc"

    with open("b:\crp9472_personal\cfms_2\content/pub.pem", "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())

    with open("b:\crp9472_personal\cfms_2\content/pri.pem", "rb") as pri_file:
        private_key = RSA.import_key(pri_file.read())

    print(public_key)
    print(private_key)
    # 加密
    pub_cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = pub_cipher.encrypt(data)
    print(encrypted_data)

    pri_cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = pri_cipher.decrypt(encrypted_data)
    print(decrypted_data.decode())