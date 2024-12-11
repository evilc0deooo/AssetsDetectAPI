# -*- coding: utf-8 -*-

import time
from common.conn import http_req
from common.base_thread import BaseThread
from common.log_msg import logger


class ProbeHTTP(BaseThread):
    """
    探测 http 服务
    """

    def __init__(self, domains, concurrency=6):
        super().__init__(self._build_targets(domains), concurrency=concurrency)

        self.sites = []
        self.domains = domains

    @staticmethod
    def _build_targets(domains):
        _targets = []
        for item in domains:
            domain = item
            if hasattr(item, 'domain'):
                domain = item.domain

            _targets.append(f'https://{domain}')
            _targets.append(f'http://{domain}')

        return _targets

    def work(self, target):
        conn = http_req(target, 'head', timeout=(3, 2))

        if conn.status_code in [502, 504, 501, 422, 410, 400]:
            logger.debug(f'{target} skipping http status {conn.status_code}')
            return

        self.sites.append(target)

    def run(self):
        t1 = time.time()
        logger.info(f'start probe http {len(self.targets)}')
        self._run()
        # 去除 https 和 http 相同的
        alive_site = []
        for x in self.sites:
            if x.startswith('https://'):
                alive_site.append(x)

            elif x.startswith('http://'):
                x_temp = 'https://' + x[7:]
                if x_temp not in self.sites:
                    alive_site.append(x)

        elapse = time.time() - t1
        logger.info(f'end probe http {len(alive_site)} elapse {elapse}')

        return alive_site


def run(domain, concurrency=10):
    """
    类统一调用入口
    """
    p = ProbeHTTP(domain, concurrency=concurrency)
    return p.run()
