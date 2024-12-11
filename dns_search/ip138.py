# -*- coding: utf-8 -*-

from common.conn import http_req
from utils.domain import match_subdomains
from common.log_msg import logger


class IP138(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'IP138Query'
        self.adder = f'https://site.ip138.com/{self.domain}/domain.htm'

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        self.subdomains = set()
        resp = http_req(self.adder)
        if not resp:
            return []

        subdomains = match_subdomains(self.domain, resp.text)
        self.subdomains.update(subdomains)

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
    query = IP138(domain)
    subdomains = query.run()
    return subdomains
