from Crypto .PublicKey import RSA
#生成一对长度为2048位的RSA秘钥对，使用默认的随机数生成函数，
# 也可以手动指定一个随机数生成函数: randfunc=Crypto.Random.new( ).read
rsa_key = RSA.generate(2048)
print( rsa_key)

print(type( rsa_key ) )
#<cLass 'crypto.PubLicKey . RSA.RsaKey ' >
#导出公钥，"PEMN”表示使用文本编码输出，返回的是 bytes类型，格式如下:
# b ' -----BEGIN PUBLIC KEY-----\n{Base64Text] \n-----END PUBLIC KEY---- -'# 输出格式可选:"PEM",”DER","OpenSSH"
pub_key = rsa_key.publickey( ).export_key ( "PEM")
#导出私钥，"PEMN”表示使用文本编码输出，返回的是bytes类型，格式如下:
# b ' -----BEGIN RSA PRTVATE KEY-----\n{Base64Text]\n-----END RSA PRIVATE KEY----- 'pri_key = rsa_key . export_key("PEM")
# 转换为文本打印输出公钥和私钥
print(pub_key. decode( ))
print(pri_key . decode( ))
