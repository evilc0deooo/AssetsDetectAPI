# -*- coding: utf-8 -*-

from urllib.parse import urlparse
from thirdparty.googlesearch import search
from common.log_msg import logger


class GoogleSpider(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'GoogleSpider'

    def query(self):
        """
        向接口查询有价值子域并做子域匹配
        """
        self.subdomains = set()
        wds = ['inurl:admin|login|register|upload|editor|system', 'admin|login|后台|系统']
        stop = 20  # 谷歌最多爬取 20 个结果
        for wd in wds:
            key = f'site:*.{self.domain} {wd}'
            for each_result in search(key, stop=stop):
                parse_ret = urlparse(each_result)
                if self.domain in parse_ret.netloc:
                    self.subdomains.add(parse_ret.netloc)

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
    query = GoogleSpider(domain)
    subdomains = query.run()
    return subdomains
