"""
initialize.py

初始化系统（主要是数据表结构）的专门程序。

定义了一些函数来有条理地处理
"""

import hashlib
import json
import os
import secrets
import sqlite3
import time
from Crypto.PublicKey import RSA

from include.bulitin_class.users import AllUsers

from include.database.operator import DatabaseOperator, getDBPool
from include.util.usertools import createGroup, createUser


def initDatabaseStructure(db_pool):
    """
    这一函数处理数据库初始化的相关步骤。
    它将创建必要的数据表并向其中插入初始数据。
    """

    DB_VERSION = 0

    ### 创建用户组数据表: users
    # 计划中的表栏目： user_id AUTOINCREMENT, username, [password, salt], nickname, status, last_login, created_time
    # 其中 status 有以下几种状态： 0 - OK, 1 - disabled (Are we really going to use this column?)

    dboptr = DatabaseOperator(db_pool)

    dboptr[1].execute(
        "CREATE TABLE users (`user_id` BIGINT PRIMARY KEY AUTO_INCREMENT, `username` varchar(255), \
            `password` TEXT, `salt` TEXT, `nickname` varchar(255), \
            `status` INTEGER, `last_login` INT, `created_time` INT);"
    )

    ### user_permissions
    # columns: user_id, perm_name, perm_type, mode, expire_time

    dboptr[1].execute(
        "CREATE TABLE user_permissions (`user_id` BIGINT PRIMARY KEY, `perm_name` varchar(255), \
            `perm_type` varchar(64), `mode` varchar(64), `expire_time` INT);"
    )

    ### user_metadata
    # columns: user_id, key, value, created_time, modified_time
    dboptr[1].execute(
        "CREATE TABLE user_metadata (`user_id` BIGINT PRIMARY KEY, `key` varchar(255), \
            `value` text, `created_time` INT, `modified_time` INT);"
    )

    createUser(
        "admin", "123456", user_groups={"sysop": -1}, all_users=AllUsers(db_pool)
    )

    # 创建用户组表及其初始数据

    dboptr[1].execute(
        "CREATE TABLE `groups` (`id` BIGINT PRIMARY KEY AUTO_INCREMENT, `g_id` VARCHAR(255), `group_name` TEXT, `status` INT"
    )
    dboptr[1].execute(
        "CREATE TABLE `group_rights` (`id` BIGINT PRIMARY KEY, `right` TEXT, `mode` VARCHAR(255), `expire_time` INT"
    )

    dboptr[1].execute(
        "CREATE TABLE group_metadata (`id` BIGINT PRIMARY KEY, `key` varchar(255), \
            `value` text, `created_time` INT, `modified_time` INT);"
    )

    # 初始化 sysop 用户组
    createGroup(
        "sysop",
        "System Operator",
        {
            "super_useravatar": 0,
            "super_access": 0,
            "view_deleted": 0,
            "permanently_delete": 0,
            "shutdown": 0,
            "create_user": 0,
            "create_dir": 0,
            "custom_new_user_settings": 0,
            "create_group": 0,
            "custom_new_group_settings": 0,
            "custom_new_group_members": 0,
            "view_others_properties": 0,
            "change_id": 0,
            "edit_other_users": 0,
            "set_usergroups": 0,
            "set_userrights": 0,
            "action_server_destroy": 0
        },
        status=0,
        dboptr=dboptr,
    )

    # 初始化 user 组
    createGroup(
        "user",
        None,
        {"read": 0},
        status=0,
        dboptr=dboptr,
    )

    ### document_indexes

    dboptr[1].execute(
        "CREATE TABLE document_indexes(`id` VARCHAR(255) PRIMARY KEY, `path` TEXT)"
    )

    ### path 存储一个相对于运行根目录的路径，将在调用时自动拼接根目录绝对路径处理

    insert_doc = (
        ("0", "/content/hello.txt"),
        ("DEFAULT_USER_AVATAR", "/content/files/user.png"),
    )

    dboptr[1].executemany("INSERT INTO document_indexes VALUES(?, ?)", insert_doc)
    dboptr[0].commit()

    #######################

    # 新建伪路径索引定义表
    dboptr[1].execute(
        "CREATE TABLE path_structures\
                (`id` VARCHAR(255) PRIMARY KEY, `name` TEXT, `owner` TEXT, `parent_id` TEXT, `type` TEXT, \
                `revisions` TEXT, `access_rules` BLOB, `external_access` BLOB, `properties` BLOB, `state` TEXT)"
    )
    # file_id: 如果是文件就必须有；文件夹应该没有

    insert_doc_access_rules = {
        "__noinherit__": [],  # 仅当上层启用继承时才有效；deny 设置有特殊格式，deny_ 开头后接 action 表示单独操作的 deny 规则不继承
        "read": [],
        "write": [],
        "deny": {
            "read": {
                "groups": {
                    # "sysop": {
                    #     "expire": 0
                    # }
                },
                "users": {},
                "rules": [],
            },
            "write": {},
        },
    }

    insert_dir_access_rules = {
        "__noinherit__": [],  # 仅当上层启用继承时才有效；deny 设置则将导致所有 deny 规则不继承
        "__subinherit__": True,  # 是否被下层所继承，如果为 False，则在判断时将返回为真；仅目录有此设置
        "read": [],
        "write": [],
        "deny": {"read": [], "write": []},
    }

    insert_doc_external_access = (
        {  # 这里的 access 下记录的是允许的操作而非权限，即：read, write, delete, permanently_delete, rename
            "groups": {
                "sysop": {"read": {"expire": 0}, "permanently_delete": {"expire": 0}}
            },
            "users": {},
        }
    )

    insert_doc_state = {"code": "ok", "expire_time": 0}

    import uuid

    insert_doc_revisions = {
        uuid.uuid4().hex: {
            "file_id": "0",
            "state": {"code": "ok", "expire_time": 0},
            "access_rules": {},
            "external_access": {},
            "time": time.time(),
        }
    }

    insert_paths = (
        (
            "the_initial",
            "hello.txt",
            json.dumps((("user", "admin"),)),
            "dir01",
            "file",
            json.dumps(insert_doc_revisions),
            json.dumps(insert_doc_access_rules),
            json.dumps(insert_doc_external_access),
            json.dumps({}),
            json.dumps(insert_doc_state),
        ),
        (
            "the_initial_dir",
            "Test Dir",
            json.dumps((("user", "admin"),)),
            "",
            "dir",
            None,
            json.dumps(insert_dir_access_rules),
            json.dumps(insert_doc_external_access),
            json.dumps({}),
            json.dumps(insert_doc_state),
        ),
    )
    dboptr[1].executemany(
        "INSERT INTO path_structures VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", insert_paths
    )

    # create config table(internal)

    dboptr[1].execute(
        "CREATE TABLE `cfms_internal`(`id` INT(4) PRIMARY KEY AUTO_INCREMENT, `key` TEXT, `value` BLOB)"
    )

    dboptr[1].execute(
        "INSERT INTO cfms_internal (`key`, `value`) VALUES(?, ?)",
        ("db_version", DB_VERSION),
    )

    # create policy table
    dboptr[1].execute(
        "CREATE TABLE `policies`(`id` VARCHAR(255) PRIMARY KEY, `content` TEXT, `access_rules` TEXT, `external_access` TEXT)"
    )

    for dirpath, dirnames, filenames in os.walk(
        f"./include/initial_policies"
    ):
        for file in filenames:
            if not file.endswith(".json"):
                continue
            with open(
                os.path.join(dirpath, file), "r", encoding="utf-8"
            ) as f:  # force utf-8
                loaded_json = json.load(f)
                policy_id = loaded_json["policy_id"]
                access_rules = loaded_json["access_rules"]
                external_access = loaded_json["external_access"]
                policy_content = loaded_json["content"]

                dboptr[1].execute(
                    "INSERT INTO `policies` VALUES(?, ?, ?, ?)",
                    (
                        policy_id,
                        json.dumps(policy_content),
                        json.dumps(access_rules),
                        json.dumps(external_access),
                    ),
                )

    dboptr[0].commit()

    # 生成一对长度为 2048 位的 RSA 秘钥对, 使用默认的随机数生成函数,
    # 也可以手动指定一个随机数生成函数: randfunc=Crypto.Random.new().read
    rsa_key = RSA.generate(4096)
    # print(rsa_key)                      # Private RSA key at 0x7FB241173748
    # print(type(rsa_key))                # <class 'Crypto.PublicKey.RSA.RsaKey'>

    # 导出公钥, "PEM" 表示使用文本编码输出, 返回的是 bytes 类型, 格式如下:
    # b'-----BEGIN PUBLIC KEY-----\n{Base64Text}\n-----END PUBLIC KEY-----'
    # 输出格式可选: "PEM", "DER", "OpenSSH"
    pub_key = rsa_key.publickey().export_key("PEM")

    # 导出私钥, "PEM" 表示使用文本编码输出, 返回的是 bytes 类型, 格式如下:
    # b'-----BEGIN RSA PRIVATE KEY-----\n{Base64Text}\n-----END RSA PRIVATE KEY-----'
    pri_key = rsa_key.export_key("PEM")

    # 转换为文本打印输出公钥和私钥
    # print(pub_key.decode())
    # print(pri_key.decode())

    # 把公钥和私钥保存到文件
    with open("content/auth/pub.pem", "wb") as pub_fp:
        pub_fp.write(pub_key)

    with open("content/auth/pri.pem", "wb") as pri_fp:
        pri_fp.write(pri_key)

    ### 新建文件传输临时列表数据库

    with open("content/fqueue.db", "a") as fqueue_file:
        fqueue_file.truncate(0)  # 清空

    fQueue_db = sqlite3.connect("./content/fqueue.db")

    fQ_cur = fQueue_db.cursor()

    # create file transport queue table
    fQ_cur.execute(
        "CREATE TABLE ft_queue\
            (task_id TEXT, username TEXT, token TEXT, operation TEXT, file_id TEXT, fake_id TEXT, fake_dir TEXT, expire_time INTEGER, done INTEGER, cleared INTEGER)"
    )
    # file_id: 存贮在 document_indexes 中的文件id
    # fake_id: 这个 id 将作为 ftp 服务中以 task_id 为账户名的用户目录下的文件名。

    fQueue_db.close()

    ### Init FTP SSL

    from OpenSSL import crypto

    sr_class = secrets.SystemRandom()  # create SystemRandom class

    ###########
    # CA Cert #
    ###########

    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    ca_cert.set_serial_number(sr_class.randint(50000000, 100000000))

    ca_subj = ca_cert.get_subject()
    ca_subj.commonName = "CFMS Self CA"

    ca_cert.add_extensions(
        [
            crypto.X509Extension(
                b"subjectKeyIdentifier", False, b"hash", subject=ca_cert
            ),
        ]
    )

    ca_cert.add_extensions(
        [
            crypto.X509Extension(
                b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert
            ),
        ]
    )

    ca_cert.add_extensions(
        [
            crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
        ]
    )

    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_key)

    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

    ca_cert.sign(ca_key, "sha256")

    # Save certificate
    with open(f"./content/auth/ca.crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode())

    # Save private key
    with open(f"./content/auth/ca.key", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode())

    ###############
    # Client Cert #
    ###############

    client_key = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA, 2048)

    client_cert = crypto.X509()
    client_cert.set_version(2)
    client_cert.set_serial_number(sr_class.randint(50000000, 100000000))

    client_subj = client_cert.get_subject()
    client_subj.commonName = "CFMS Server self-signed"

    client_cert.add_extensions(
        [
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            crypto.X509Extension(
                b"subjectKeyIdentifier", False, b"hash", subject=client_cert
            ),
        ]
    )

    client_cert.add_extensions(
        [
            crypto.X509Extension(
                b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert
            ),
            crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth"),
            crypto.X509Extension(b"keyUsage", False, b"digitalSignature"),
        ]
    )

    client_cert.set_issuer(ca_subj)
    client_cert.set_pubkey(client_key)

    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

    client_cert.sign(ca_key, "sha256")

    # print(crypto.dump_certificate(crypto.FILETYPE_TEXT, client_cert))

    # Save certificate
    with open(f"./content/auth/ftp_client.crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode())

    # Save private key
    with open(f"./content/auth/ftp_client.key", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode())