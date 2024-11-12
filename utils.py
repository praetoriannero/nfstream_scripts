import os


def gather_files(path):
    files = []
    if os.path.isfile(path):
        files.append(path)

    elif os.path.isdir(path):
        for node in os.listdir(path):
            full_path = os.path.join(path, node)
            files.append(full_path)

    files = [file for file in files if "lock" not in file]
    return files


def ip_to_str(buf):
    return ".".join([str(val) for val in buf])
