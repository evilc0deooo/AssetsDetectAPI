# -*- coding: utf-8 -*-

import time
from common.conn import http_req
from utils.domain import match_subdomains
from common.log_msg import logger


class Bing(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'BingQuery'
        self.delay = 1.5
        self.init = 'https://www.bing.com/'
        self.adder = 'https://www.bing.com/search'

    def query(self):
        """
        向接口查询子域并做子域匹配
        """
        page_num = 1  # 二次搜索重新置0
        limit_num = 100  # 限制搜索条数
        per_page_num = 50  # 每页显示搜索条数
        self.subdomains = set()
        resp = http_req(self.init, allow_redirects=True)
        if not resp:
            return []

        cookies = resp.cookies  # 获取 Cookie Bing 在搜索时需要带上 Cookie
        while True:
            time.sleep(self.delay)
            params = {'q': f'site:{self.domain}', 'first': page_num, 'count': per_page_num}
            resp2 = http_req(self.adder, params=params, cookies=cookies)
            if resp2.status_code != 200:
                break
            subdomains = match_subdomains(self.domain, resp2.text)
            self.subdomains.update(subdomains)
            if not subdomains:  # 搜索没有发现子域名则停止搜索
                break

            if '<div class="sw_next">' not in resp2.text:  # 搜索页面没有出现下一页时停止搜索
                break

            page_num += per_page_num
            if subdomains.issubset(self.subdomains):  # 在全搜索过程中发现搜索出的结果有完全重复的结果就停止搜索
                break

            if page_num >= limit_num:  # 搜索条数限制
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

        logger.info(f'source module {self.source} found {len(self.subdomains)} subdomains')
        return subdomains


def run(domain):
    """
    类统一调用入口
    :param str domain: 域名
    """
    query = Bing(domain)
    subdomains = query.run()
    return subdomains
