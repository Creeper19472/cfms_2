import sys

def convertFile2PathID(file_id_dict: dict, path_id_dict: dict):
    
    if len(file_id_dict) > len(path_id_dict):
        raise KeyError("no enough keys to map")

    return_dict = {}

    for i in file_id_dict:
        for k in path_id_dict:
            if path_id_dict[k] == i:
                return_dict[k] = file_id_dict[i]
                break

    if len(return_dict) != len(file_id_dict):
        raise KeyError("not all file ids matched well")

    return return_dict

if __name__ == "__main__":
    mapping = {
        "": "avatar_file_id",
        "EXAMPLE_DIR": "aaa"
    }

    file_id_dict = {
        "avatar_file_id": "ajk27tq2tg",
        "aaa": "aiy398yt9gw"
    }

    print(convertFile2PathID(file_id_dict, mapping))