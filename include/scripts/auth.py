

from include.bulitin_class.policies import Policies
from include.bulitin_class.users import Users

import time
import json

def handle_login(instance, req_username, req_password):
    # 初始化用户对象 User()
    user = Users(req_username, instance.db_conn, instance.db_cursor)
    if user.ifExists():
        if user.ifMatchPassword(req_password):  # actually hash
            instance.log.logger.info(f"{req_username} 密码正确，准予访问")
            user.load()  # 载入用户信息

            # 读取 token_secret
            with open(
                f"{instance.root_abspath}/content/auth/token_secret", "r"
            ) as ts_file:
                token_secret = ts_file.read()

            instance.__send(
                json.dumps(
                    {
                        "code": 0,
                        "token": user.generateUserToken(
                            ("all"), 3600, token_secret
                        ),
                        "ftp_port": instance.config["connect"]["ftp_port"],
                    }
                )
            )

        else:
            instance.log.logger.info(f"{req_username} 密码错误，拒绝访问")

            user_auth_policy = Policies("user_auth", instance.db_conn, instance.db_cursor)
            sleep_for_fail = user_auth_policy["sleep_when_login_fail"]

            if sleep_for_fail:
                instance.log.logger.debug(f"正根据登录策略睡眠 {sleep_for_fail} 秒")
                time.sleep(sleep_for_fail)

            if instance.config["security"]["show_login_fail_details"]:
                fail_msg = "password incorrect"
            else:
                fail_msg = "username or password incorrect"

            instance.__send(json.dumps({"code": 401, "msg": fail_msg}))
    else:
        if instance.config["security"]["show_login_fail_details"]:
            fail_msg = "user does not exist"
        else:
            fail_msg = "username or password incorrect"

        user_auth_policy = Policies("user_auth", instance.db_conn, instance.db_cursor)
        sleep_for_fail = user_auth_policy["sleep_when_login_fail"]

        if sleep_for_fail:
            instance.log.logger.debug(f"正根据登录策略睡眠 {sleep_for_fail} 秒")
            time.sleep(sleep_for_fail)

        instance.__send(json.dumps({"code": 401, "msg": fail_msg}))

def handle_logout(instance):
    pass

def handle_refreshToken(instance, loaded_recv):
    old_token = loaded_recv["auth"]["token"]
    req_username = loaded_recv["auth"]["username"]

    user = Users(req_username, instance.db_conn, instance.db_cursor)  # 初始化用户对象
    # 读取 token_secret
    with open(f"{instance.root_abspath}/content/auth/token_secret", "r") as ts_file:
        token_secret = ts_file.read()

    if new_token := user.refreshUserToken(
        old_token, token_secret, vaild_time=3600
    ):  # return: {token} , False
        instance.__send(json.dumps({"code": 0, "msg": "ok", "token": new_token}))
    else:
        instance.__send(json.dumps({"code": 401, "msg": "invaild token or username"}))