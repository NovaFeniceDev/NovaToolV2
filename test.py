import platform
import os

def get_os_info():
    os_info = {}

    os_info['system'] = platform.system()
    os_info['release'] = platform.release()
    os_info['version'] = platform.version()

    return os_info


print(get_os_info())