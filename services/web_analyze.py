# -*- coding: utf-8 -*-

import time
import json
import os
import thirdparty
from thirdparty import PHANTOMJS, PHANTOMJS_ARM, DRIVER_JS
from common.base_thread import BaseThread
from common.log_msg import logger


class WebAnalyze(BaseThread):
    def __init__(self, sites, concurrency=3):
        super().__init__(sites, concurrency=concurrency)
        self.analyze_map = {}
        architecture = thirdparty.get_architecture()
        if architecture == 'ARM':
            self.phantomjs = PHANTOMJS_ARM
        else:
            self.phantomjs = PHANTOMJS

        os.chmod(self.phantomjs, 0o777)

    def work(self, site):
        cmd_parameters = [f'{self.phantomjs}',
                          '--ignore-ssl-errors true',
                          '--ssl-protocol any',
                          '--ssl-ciphers ALL',
                          f'{DRIVER_JS}',
                          site]

        output = thirdparty.check_output(cmd_parameters, timeout=20)
        output = output.decode('utf-8')
        self.analyze_map[site] = json.loads(output)['applications']

    def run(self):
        t1 = time.time()
        logger.info(f'start web analyze {len(self.targets)}')
        self._run()
        elapse = time.time() - t1
        logger.info(f'end web analyze elapse {elapse}')
        return self.analyze_map


def run(sites, concurrency=2):
    """
    类统一调用入口
    """
    s = WebAnalyze(sites, concurrency=concurrency)
    return s.run()
