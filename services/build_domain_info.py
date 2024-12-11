# -*- coding: utf-8 -*-

import time
from services.resolver import DomainInfo
from common.base_thread import BaseThread
from utils.domain import get_ip, get_cname
from common.log_msg import logger


class BuildDomainInfo(BaseThread):
    def __init__(self, domains, concurrency=6):
        super().__init__(domains, concurrency=concurrency)

        self.domain_info_list = []

    def work(self, target):
        domain = target
        if hasattr(target, 'domain'):
            domain = target.domain

        # 不记录日志
        ips = get_ip(domain, log_flag=False)
        if not ips:
            return

        cnames = get_cname(domain, log_flag=False)

        info = {
            'domain': domain,
            'type': 'A',
            'record': ips,
            'ips': ips
        }

        if cnames:
            info['type'] = 'CNAME'
            info['record'] = cnames

        self.domain_info_list.append(DomainInfo(**info))

    def run(self):
        """
        构建域名信息
        """
        t1 = time.time()
        logger.info('start build Domain info {}'.format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        logger.info('end build Domain info {} elapse {}'.format(len(self.domain_info_list), elapse))

        return self.domain_info_list


def run(domains, concurrency=15):
    """
    类统一调用入口
    """
    p = BuildDomainInfo(domains, concurrency=concurrency)
    return p.run()
