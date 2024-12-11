# -*- coding: utf-8 -*-

from common.conn import http_req
from utils.domain import match_subdomains
from common.log_msg import logger
from config import SHODAN_API


class ShodanAPI(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'ShodanAPISearch'
        self.key = SHODAN_API
        self.adder = f'https://api.shodan.io/dns/domain/{self.domain}?key={self.key}'
        self.delay = 3

    def query(self):
        """
        发送搜索请求并做子域匹配
        """
        if self.key == 'NULL':
            return []

        self.subdomains = set()
        resp = http_req(self.adder)
        if not resp:
            return []

        if '401 Unauthorized' in resp.text or resp.status_code == 401:
            logger.error(f'source module {self.source} api key error.')
            return []

        if resp.status_code == 200:
            data = resp.json()
            names = data.get('subdomains')
            subdomain_str = str(set(map(lambda name: f'{name}.{self.domain}', names)))
            subdomains = match_subdomains(self.domain, subdomain_str)
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
    query = ShodanAPI(domain)
    subdomains = query.run()
    return subdomains
