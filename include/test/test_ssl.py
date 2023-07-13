def generate_adhoc_ssl_pair(cn=None):
    from datetime import datetime as dt
    from datetime import timedelta
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        raise TypeError("Using ad-hoc certificates requires the cryptography library.")
    pkey = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # pretty damn sure that this is not actually accepted by anyone
    if cn is None:
        cn = u"*"

    # subject：使用者
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "我自己"),
            x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'cn'),
        ]
    )

    # issuer：颁发者
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "我自己"),
            x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'cn'),
        ]
    )

    # cert使用私钥签名（.sign(私钥，摘要生成算法，填充方式)），使用x509.CertificateBuilder()方法生成证书，证书属性使用下列函数叠加补充
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pkey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.utcnow() + timedelta())
        .not_valid_after(dt.utcnow() + timedelta(days=365)).sign(pkey, hashes.SHA256(), default_backend())
    )
    # 最终生成的证书与密钥对为类对象，要保存在文件中还需要进一步转换成字节格式
    return cert, pkey


if __name__ == '__main__':
    import OpenSSL
    from cryptography.hazmat.primitives import serialization
    cert, pkey = generate_adhoc_ssl_pair()
    print(cert)
    # 将证书类对象转换成PEM格式的字节串
    cert_text = cert.public_bytes(serialization.Encoding.PEM)
    print(cert_text)
    # 将证书字节串保存到文件中
    with open('self_signed.cer', mode='wb') as cert_file:
        cert_file.write(cert_text)

    # 将私钥类对象转换成PEM格式的字节串，encryption_algorithm=serialization.NoEncryption()这里是私钥不加密的意思
    private_text = pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    print(private_text)
    # 将私钥字节串保存到文件中
    with open('self_signed_pkey.key', mode='wb') as pkey_file:
        pkey_file.write(private_text)

    # 在程序中查看证书文件内容，当然也可以在文件夹中去双击self_signed.cer查看
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                           cert_text)

    certIssue = cert.get_issuer()
    print("通用名称：           ", cert.get_subject().CN)
    print("机构名：             ", cert.get_subject().O)
    print("机构单元名称：        ", cert.get_subject().OU)
    print("地理位置：            ", cert.get_subject().L)
    print("州/省名：             ", cert.get_subject().ST)
    print("国名：               ", cert.get_subject().C)
    print("证书版本:            ", cert.get_version() + 1)
    print("证书序列号:          ", hex(cert.get_serial_number()))
    print("证书中使用的签名算法: ", cert.get_signature_algorithm().decode("UTF-8"))
    print("颁发者:              ", certIssue.commonName)
    print("有效期从:             ", cert.get_notBefore())
    print("到:                   ", cert.get_notAfter())
    print("证书是否已经过期:      ", cert.has_expired())
    print("公钥长度", cert.get_pubkey().bits())
    print("公钥:\n", OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM,
                                                 cert.get_pubkey()).decode(
        "utf-8"))
    print("主体信息:")

    print("CN : 通用名称  OU : 机构单元名称")
    print("O  : 机构名    L  : 地理位置")
    print("S  : 州/省名   C  : 国名")

    for item in certIssue.get_components():
        print(item[0].decode("utf-8"), "  ——  ", item[1].decode("utf-8"))

    print(cert.get_extension_count())