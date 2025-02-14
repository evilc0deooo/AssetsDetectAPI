# -*- coding: utf-8 -*-

from common.conn import http_req
from utils.domain import match_subdomains
from common.log_msg import logger


class WebArchiveQuery(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'WebArchiveQuery'
        self.adder = 'https://web.archive.org/cdx/search/cdx?output=txt&fl=original&collapse=urlkey&page=&url=*.'

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        self.adder = f'{self.adder}{self.domain}'
        self.subdomains = set()
        resp = http_req(self.adder, timeout=60)
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
    query = WebArchiveQuery(domain)
    subdomains = query.run()
    return subdomains
