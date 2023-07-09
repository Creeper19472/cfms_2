import random


def a():
    ### Init FTP SSL

    from OpenSSL import crypto

    ###########
    # CA Cert #
    ###########

    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    ca_cert.set_serial_number(random.randint(50000000,100000000))

    ca_subj = ca_cert.get_subject()
    ca_subj.commonName = "My CA"

    ca_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
        crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
    ])

    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_key)

    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10*365*24*60*60)

    ca_cert.sign(ca_key, 'sha256')

    # Save certificate
    with open(f"{root_abspath}/content/auth/ca.crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode())

    # Save private key
    with open(f"{root_abspath}/content/auth/ca.key", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode())

    ###############
    # Client Cert #
    ###############

    client_key = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA, 2048)

    client_cert = crypto.X509()
    client_cert.set_version(2)
    client_cert.set_serial_number(random.randint(50000000,100000000))

    client_subj = client_cert.get_subject()
    client_subj.commonName = "Client"

    client_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=client_cert),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
        crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth"),
        crypto.X509Extension(b"keyUsage", False, b"digitalSignature"),
    ])

    client_cert.set_issuer(ca_subj)
    client_cert.set_pubkey(client_key)

    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(10*365*24*60*60)

    client_cert.sign(ca_key, 'sha256')

    # print(crypto.dump_certificate(crypto.FILETYPE_TEXT, client_cert))

    # Save certificate
    with open(f"{root_abspath}/content/auth/ftp_client.crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode())

    # Save private key
    with open(f"{root_abspath}/content/auth/ftp_client.key", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode())

if __name__ == "__main__":
    global root_abspath

    root_abspath = "."

    a()