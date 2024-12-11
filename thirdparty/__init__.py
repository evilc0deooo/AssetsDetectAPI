# -*- coding: utf-8 -*-

import hashlib
import os
import pathlib
import random
import shlex
import string
import subprocess
import time
import json
import platform

base_directory = pathlib.Path(__file__).parent.parent

MASSDNS_ARM_BIN = os.path.join(base_directory, 'thirdparty/massdns/massdns_darwin_arm64')
MASSDNS_ARCH_BIN = os.path.join(base_directory, 'thirdparty/massdns/massdns_linux_aarch64')
PHANTOMJS_ARM = os.path.join(base_directory, 'thirdparty/phantomjs/phantomjs_arm')
OBSERVER_ARM = os.path.join(base_directory, 'thirdparty/observer/observer_ward')

MASSDNS_BIN = os.path.join(base_directory, 'thirdparty/massdns/massdns_linux_x86_64')
PHANTOMJS = os.path.join(base_directory, 'thirdparty/phantomjs/phantomjs')
OBSERVER_BIN = os.path.join(base_directory, 'thirdparty/observer/observer_linux')

SCREENSHOT_JS = os.path.join(base_directory, 'thirdparty/screenshot/screenshot.js')
SCREENSHOT_DIR = os.path.join(base_directory, 'thirdparty/screenshot/tmp_screenshot')
SCREENSHOT_FAIL_IMG = os.path.join(base_directory, 'thirdparty/screenshot/screenshot_fall_img.png')
DRIVER_JS = os.path.join(base_directory, 'thirdparty/driver/driver.js')

TMP_PATH = os.path.join(base_directory, 'thirdparty/tmp')
if not os.path.exists(TMP_PATH):
    os.mkdir(TMP_PATH)


def load_file(path):
    with open(path, 'r+', encoding='utf-8') as f:
        return f.readlines()


def load_json(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as fp:
        return json.load(fp)


def random_choices(k=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))


def gen_md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def curr_date(secs):
    """
    获取当前时间 2024-01-14 03:33:51
    """
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(secs))


def exec_system(cmd, **kwargs):
    cmd = ' '.join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs['timeout']
        kwargs.pop('timeout')

    completed = subprocess.run(shlex.split(cmd), timeout=timeout, check=False, close_fds=True, **kwargs)

    return completed


def check_output(cmd, **kwargs):
    cmd = ' '.join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs.pop('timeout')

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')

    output = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, timeout=timeout, check=False, **kwargs).stdout
    return output


def get_architecture():
    """
    判断当前机器架构信息
    """
    machine = platform.machine()
    if 'arm' in machine.lower():
        return 'ARM'
    elif 'aarch64' in machine.lower():
        return 'ARCH'
    elif '64' in platform.architecture()[0]:
        return '64-bit Intel/AMD'
    else:
        return '32-bit Intel/AMD'
