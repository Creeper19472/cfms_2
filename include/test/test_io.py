


# 开始创建文件

import datetime
import secrets
import os

root_abspath = "B:\crp9472_personal\cfms_2"

index_file_id = secrets.token_hex(64) # 存储在 document_indexes 中
real_filename = secrets.token_hex(32)

today = datetime.date.today()

destination_path = f"{root_abspath}/content/file/{today.year}/{today.month}/"

os.makedirs(destination_path)

with open(f"{destination_path}/{real_filename}", "w") as new_file:
    pass