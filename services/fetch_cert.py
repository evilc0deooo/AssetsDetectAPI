# -*- coding: utf-8 -*-

import time
from utils.cert import get_cert
from utils.ip import IPInfo
from utils.ip import is_vaild_ip_target
from common.base_thread import BaseThread
from common.log_msg import logger


class FetchCert(BaseThread):
    def __init__(self, targets, concurrency=6):
        super().__init__(targets, concurrency=concurrency)
        self.fetch_map = {}

    def work(self, target):
        ip, port = target.split(':')
        cert = get_cert(ip, int(port))
        if cert:
            self.fetch_map[target] = cert

    def run(self):
        t1 = time.time()
        logger.info(f'start fetch cert {len(self.targets)}')
        self._run()
        elapse = time.time() - t1
        logger.info(f'end fetch cert elapse {elapse}')
        return self.fetch_map


def run(targets, concurrency=15):
    """
    类统一调用入口
    """
    f = FetchCert(targets, concurrency=concurrency)
    return f.run()


class SSLCert(object):
    def __init__(self, ip_info_list, base_domain=None):
        self.ip_info_list = ip_info_list
        self.base_domain = base_domain

    def run(self):
        target_temp_list = []
        for info in self.ip_info_list:
            if isinstance(info, IPInfo):
                for port_info in info.port_info_list:
                    port_id = port_info.port_id
                    if port_id == 80:
                        continue

                    target_temp1 = '{}:{}'.format(info.ip, port_id)
                    target_temp_list.append(target_temp1)

            elif isinstance(info, str) and is_vaild_ip_target(info):
                target_temp_list.append('{}:443'.format(info))

            elif isinstance(info, str) and ':' in info:
                target_temp_list.append(info)

        cert_map = run(target_temp_list)

        for target in cert_map:
            print(target)

        return cert_map
