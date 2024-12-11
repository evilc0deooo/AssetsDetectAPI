# -*- coding: utf-8 -*-

import os
import thirdparty
from thirdparty import OBSERVER_ARM, OBSERVER_BIN, TMP_PATH
from config import OBSERVER_FINGER_PATH, OBSERVER_CONCURRENT
from common.log_msg import logger


class Observer(object):
    def __init__(self, sites=None, observer_bin=None, tmp_dir=None, concurrent=0):
        self.concurrent = concurrent
        if self.concurrent == 0:
            self.concurrent = 200

        self.sites = sites
        self.observer_bin = observer_bin
        self.tmp_dir = tmp_dir
        self.observer_sites_path = os.path.join(self.tmp_dir, f'observer_sites_{thirdparty.random_choices()}')
        self.observer_output_path = os.path.join(self.tmp_dir, f'observer_{thirdparty.random_choices()}')
        self.observer_res_list = list()
        self.fingerprint_path = OBSERVER_FINGER_PATH
        os.chmod(self.observer_bin, 0o777)

    def gen_sites(self):
        """
        生成 Observer 目标文件
        """
        count = 0
        for _target in self.sites:
            if not _target:
                continue
            count += 1
            print(_target)
            with open(self.observer_sites_path, 'a', encoding='utf-8', errors='ignore') as f:
                f.write(_target + '\n')
        logger.info(f'observer gen targets count {count}')

    @staticmethod
    def str_to_hex(s):
        """
        文本转16进制
        """
        return ''.join([hex(ord(c)).replace('0x', '') for c in s])

    @staticmethod
    def check_is_encode_error(s):
        """
        检测中文字符乱码
        """
        try:
            s.encode('gbk')
        except UnicodeEncodeError:
            return True
        return False

    def observer_exec(self):
        """
        侦查守卫功能点
        """
        if not self.observer_sites_path:
            return

        command = [self.observer_bin,
                   f'--thread {self.concurrent}',
                   f'--fpath {self.fingerprint_path}',
                   f'--file {self.observer_sites_path}',
                   '--timeout 15',
                   f'--json {self.observer_output_path}'
                   ]

        thirdparty.exec_system(command, timeout=5 * 24 * 60 * 60)

    def parse_observer_output(self):
        ob_res_list = []
        json_data = thirdparty.load_json(self.observer_output_path)
        for data in json_data:
            is_web = data['is_web']
            if not is_web:
                continue
            url = data['url']
            name = data['name']
            length = data['length']
            title = data['title']

            # 只输出存在指纹的站点信息
            if not name:
                continue

            # 旧问题: 解决中文乱码插入 Mysql 数据库报错问题
            if self.check_is_encode_error(title):
                title = self.str_to_hex(data['title'])
                title = title[:20]

            # 旧问题: 临时修复标题过长问题
            if len(title) > 100:
                title = title[:99]

            status_code = data['status_code']
            ob_res_dict = {
                'url': url,
                'name': name,
                'length': length,
                'title': title,
                'status_code': status_code
            }

            if ob_res_dict not in ob_res_list:
                ob_res_list.append(ob_res_dict)

        self._delete_file()
        return ob_res_list

    def _delete_file(self):
        try:
            os.unlink(self.observer_sites_path)
            os.unlink(self.observer_output_path)
        except Exception as e:
            logger.warning(e)

        logger.info(f'observer delete file success')

    def run(self):
        """
        类执行入口
        """
        self.gen_sites()
        self.observer_exec()
        output = self.parse_observer_output()
        return output


def run(sites):
    """
    类统一调用入口
    """
    logger.info(f'observer start execution')

    architecture = thirdparty.get_architecture()
    if architecture == 'ARM':  # 针对 Apple M1 芯片进行判断
        obs = Observer(sites=sites, observer_bin=OBSERVER_ARM, tmp_dir=TMP_PATH, concurrent=OBSERVER_CONCURRENT)
    else:
        obs = Observer(sites=sites, observer_bin=OBSERVER_BIN, tmp_dir=TMP_PATH, concurrent=OBSERVER_CONCURRENT)

    logger.info(f'observer end execution')
    return obs.run()


if __name__ == '__main__':
    site_list = ['http://ng.zxebike.com', 'https://display.zxebike.com', 'https://enterprise.zxebike.com',
                 'https://localserver.zxebike.com', 'https://tm.zxebike.com', 'https://youyan.zxebike.com',
                 'https://images.zxebike.com', 'https://zxebike.com', 'https://www.zxebike.com',
                 'https://enterprise.zxebike.com/login/login']
    res = run(site_list)
    print(res)
