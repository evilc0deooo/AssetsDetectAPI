# -*- coding: utf-8 -*-

import os
import re
import time
import thirdparty
from thirdparty import PHANTOMJS, PHANTOMJS_ARM
from thirdparty import SCREENSHOT_JS, SCREENSHOT_DIR
from common.base_thread import BaseThread
from common.log_msg import logger


def gen_filename(site):
    """
    生成合规文件名称
    """
    filename = site.replace('://', '_')
    return re.sub('[^\w\-_]', '_', filename)


class SiteScreenshot(BaseThread):
    def __init__(self, sites, concurrency=3, capture_dir=SCREENSHOT_DIR):
        super().__init__(sites, concurrency=concurrency)
        self.capture_dir = capture_dir
        self.screenshot_map = {}
        architecture = thirdparty.get_architecture()
        if architecture == 'ARM':
            self.phantomjs = PHANTOMJS_ARM
        else:
            self.phantomjs = PHANTOMJS

        os.chmod(self.phantomjs, 0o777)
        os.makedirs(self.capture_dir, 0o777, True)

    def work(self, site):
        file_name = f'{self.capture_dir}/{gen_filename(site)}.jpg'
        cmd_parameters = [f'{PHANTOMJS}',
                          '--ignore-ssl-errors true',
                          '--ssl-protocol any',
                          '--ssl-ciphers ALL',
                          SCREENSHOT_JS,
                          f'-u={site}',
                          f'-s={file_name}',
                          ]

        thirdparty.exec_system(cmd_parameters)

        self.screenshot_map[site] = file_name

    def run(self):
        t1 = time.time()
        logger.info(f'start screen shot {len(self.targets)}.')
        self._run()
        elapse = time.time() - t1
        logger.info(f'fend screen shot elapse {elapse}.')


def run(sites, concurrency=3, capture_dir=SCREENSHOT_DIR):
    """
    类统一调用入口
    """
    s = SiteScreenshot(sites, concurrency=concurrency, capture_dir=capture_dir)
    s.run()
