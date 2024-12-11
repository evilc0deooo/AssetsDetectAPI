# -*- coding: utf-8 -*-

import time
from common.conn import http_req
from utils.domain import match_subdomains
from common.log_msg import logger
from config import VIRUSTOTAL_KEY


class Virustotal(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'VirustotalQuery'
        self.adder = f'https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains'
        self.delay = 20
        self.key = VIRUSTOTAL_KEY

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        if self.key == 'NULL':
            return []

        headers = {'X-Apikey': self.key}
        self.subdomains = set()

        resp = http_req(self.adder, headers=headers)

        if resp.status_code == 401:
            logger.error(f'source module {self.source} api key error.')
            return []

        subdomains = match_subdomains(self.domain, resp.text)
        self.subdomains.update(subdomains)
        time.sleep(self.delay)  # 免费 API 一分钟内只能使用 4 次查询

    def run(self):
        """
        类执行入口
        """
        try:
            self.query()
            subdomains = {'source_name': self.source, 'subdomains': list(self.subdomains)}
        except Exception as e:
            logger.error(f'source module {self.source} error info {e} over')
            return

        logger.info(f'source module {self.source} search {self.domain} found {len(self.subdomains)} subdomains')
        return subdomains


def run(domain):
    """
    类统一调用入口
    :param str domain: 域名
    """
    query = Virustotal(domain)
    subdomains = query.run()
    return subdomains
