from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes

from Crypto.Util.Padding import pad, unpad

# 生成一个32字节的随机密钥

key = get_random_bytes(32)

# 加密

def aes_encrypt(plain_text, key):

    cipher = AES.new(key, AES.MODE_CBC) # 使用CBC模式

    encrypted_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))

    iv = cipher.iv

    return iv + encrypted_text

# 解密

def aes_decrypt(encrypted_text, key):

    iv = encrypted_text[:16]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_text = unpad(cipher.decrypt(encrypted_text[16:]), AES.block_size)

    return decrypted_text.decode()

# 示例

plain_text = "这是一个需要加密的文本。"

encrypted_text = aes_encrypt(plain_text, key)

decrypted_text = aes_decrypt(encrypted_text, key)

print("原始文本：", plain_text)

print("加密后的文本：", encrypted_text)

print("解密后的文本：", decrypted_text)