# -*- coding: utf-8 -*-

from common.conn import http_req
from utils.domain import match_subdomains
from common.log_msg import logger
from config import ZOOMEYE_KEY


class Zoomeye(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'ZoomeyeQuery'
        self.adder = 'https://api.zoomeye.org/host/search'
        self.api_key = ZOOMEYE_KEY

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        if self.api_key == 'NULL':
            return []

        headers = {'API-KEY': self.api_key, 'Content-Type': 'application/json'}
        params = {
            'query': f'(site:{self.domain} hostname:{self.domain} (ssl:"{self.domain}"+ssl.cert.availability:1))'
                     f'+service:"http"'
        }
        self.subdomains = set()
        resp = http_req(self.adder, params=params, headers=headers)
        if not resp:
            return []

        if resp.status_code == 403:
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
    query = Zoomeye(domain)
    subdomains = query.run()
    return subdomains
