# -*- coding: utf-8 -*-

import time
import base64
import datetime
import json
from common.conn import http_req
from common.log_msg import logger
from config import HUNTER_KEY


class Hunter(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'HunterAPISearch'
        self.adder = 'https://api.hunter.how/search'
        self.api_key = HUNTER_KEY
        self.page_size = 100
        self.max_page = 1

    def query(self):
        """
        发送搜索请求并做子域匹配
        """
        if self.api_key == 'NULL':
            return []

        query = f'domain.suffix="{self.domain}"'
        encoded_query = base64.urlsafe_b64encode(query.encode('utf-8')).decode('ascii')
        self.subdomains = set()

        end_time = datetime.datetime.now()  # 获取当前日期时间
        start_time = end_time - datetime.timedelta(days=90)
        end_time = end_time.strftime('%Y-%m-%d')
        start_time = start_time.strftime('%Y-%m-%d')
        params = {'api-key': self.api_key,
                  'query': encoded_query,
                  'page': 1,
                  'page_size': self.page_size,
                  'start_time': start_time,
                  'end_time': end_time}

        subdomains_list = list()
        current_page = 1
        while True:
            params['page'] = current_page
            resp = http_req(self.adder, params=params)
            if not resp:
                break

            if 'Token expired' in resp.text:
                logger.error(f'source module {self.source} api key expired error over')
                break

            if 'Exceed the daily query usage' in resp.text:
                logger.error(f'source module {self.source} exceed the daily query usage, try again tomorrow')
                break

            if resp.status_code != 200 and 'success' not in resp.text:
                break

            results = json.loads(resp.text)
            arr = results['data']['list']
            if arr is None:
                break

            try:
                for host in arr:
                    subdomain = host['domain']
                    subdomains_list.append(subdomain)
            except:
                continue

            if len(arr) < self.page_size:
                break

            # 所有 API 均受每 2 秒 1 个请求的速率限制
            time.sleep(2)
            current_page += 1

        self.subdomains.update(subdomains_list)

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
    query = Hunter(domain)
    subdomains = query.run()
    return subdomains
