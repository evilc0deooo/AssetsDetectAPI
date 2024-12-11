# -*- coding: utf-8 -*-

import time
from bs4 import BeautifulSoup
from common.conn import http_req
from utils.domain import match_subdomains
from common.log_msg import logger


class Gitee(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'GiteeSearch'
        self.adder = 'https://search.gitee.com/'
        self.delay = 3

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        self.subdomains = set()
        page_num = 1
        while True:
            time.sleep(self.delay)
            params = {
                'pageno': page_num,
                'q': self.domain,
                'type': 'code'
            }
            try:
                resp = http_req(self.adder, params=params)
            except:
                return []

            if not resp:
                return []

            if resp.status_code != 200:
                return []

            if 'class="empty-box"' in resp.text:
                return []

            soup = BeautifulSoup(resp.text, 'html.parser')
            subdomains = match_subdomains(self.domain, str(soup))
            self.subdomains.update(subdomains)

            if not subdomains:
                return []

            if subdomains.issubset(self.subdomains):
                return []

            if '<li class="disabled"><a href="###">' in resp.text:
                return []

            page_num += 1
            if page_num >= 100:
                break

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
    query = Gitee(domain)
    subdomains = query.run()
    return subdomains
