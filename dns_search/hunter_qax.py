# -*- coding: utf-8 -*-

import base64
import datetime
import json
import time
from common.conn import http_req
from common.log_msg import logger
from config import QAX_HUNTER_KEY


class QaxHunter(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'QaxHunterAPISearch'
        self.adder = 'https://hunter.qianxin.com/openApi/search'
        self.api_key = QAX_HUNTER_KEY
        self.page_size = 100
        self.max_page = 1

    def query(self):
        """
        发送搜索请求并做子域匹配
        """
        if self.api_key == 'NULL':
            return []

        subdomain_encode = f'domain.suffix="{self.domain}"'
        query_data = base64.urlsafe_b64encode(subdomain_encode.encode('utf-8'))
        self.subdomains = set()
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(days=180)
        end_time = end_time.strftime('%Y-%m-%d')
        start_time = start_time.strftime('%Y-%m-%d')
        params = {'api-key': self.api_key,
                  'search': query_data,
                  'page': 1,
                  'page_size': self.page_size,
                  'is_web': 1,
                  'port_filter': 'false',
                  'status_code': '200,404,403,301,302',
                  'start_time': start_time,
                  'end_time': end_time}

        subdomains_list = list()
        current_page = 1
        while True:
            params['page'] = current_page
            resp = http_req(self.adder, params=params)

            if resp.status_code != 200 or 'account_type' not in resp.text:
                break

            results = json.loads(resp.text)
            arr = results['data']['arr']
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

            time.sleep(2)
            current_page += 1

            if current_page > self.max_page:
                break

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
    query = QaxHunter(domain)
    subdomains = query.run()
    return subdomains
