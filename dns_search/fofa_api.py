# -*- coding: utf-8 -*-

import base64
from common.conn import http_req
from utils.domain import match_subdomains
from common.log_msg import logger
from config import FOFA_MAIL, FOFA_KEY


class FoFa(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'FoFaAPISearch'
        self.adder = 'https://fofa.info/api/v1/search/all'
        self.email = FOFA_MAIL
        self.key = FOFA_KEY

    def query(self):
        """
        发送搜索请求并做子域匹配
        """
        if self.email == 'NULL' or self.key == 'NULL':
            return []

        subdomain_encode = f'domain="{self.domain}"'.encode('utf-8')
        query_data = base64.b64encode(subdomain_encode).decode('utf-8')
        self.subdomains = set()
        params = {'email': self.email,
                  'key': self.key,
                  'qbase64': query_data,
                  'full': 'true',
                  'size': 10000}

        resp = http_req(self.adder, params=params)

        if not resp:
            return []

        if resp.status_code != 200 or 'errmsg' in resp.text:
            logger.error(f'source module {self.source} api key error over')
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
    query = FoFa(domain)
    subdomains = query.run()
    return subdomains
