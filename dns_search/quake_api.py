# -*- coding: utf-8 -*-

import json
from common.conn import http_req
from common.log_msg import logger
from config import QUAKE_TOKEN


class Quake(object):
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = None
        self.source = 'QuakeAPISearch'
        self.adder = 'https://quake.360.net/api/v3/search/quake_service'
        self.token = QUAKE_TOKEN
        self.delay = 1

    def query(self):
        """
        发送搜索请求并做子域匹配
        """
        if self.token == 'NULL':
            return []

        headers = {'X-QuakeToken': self.token, 'Content-Type': 'application/json'}
        self.subdomains = set()
        data = {
            'query': f'domain:{self.domain}',
            'start': 0,
            'size': 5000,  # 查询条数：注册用户：每个月3000条、高级会员：每个月30000条、终身会员：每个月50000条
            'ignore_cache': True,  # 是否忽略缓存
            'latest': True,
            'include': ['service.http.host']
        }
        resp = http_req(self.adder, method='post', json=data, headers=headers)
        if not resp:
            return []

        if 'u3005' in resp.text:
            logger.error(f'source module {self.source} 访问已被限速, 请输入验证码.')
            return []

        if 'u3007' in resp.text:
            logger.error(f'source module {self.source} 用户积分不足.')
            return []

        if resp.status_code == 200 and '0' in resp.text:
            results = json.loads(resp.text)
            subdomains_list = list()
            try:
                for host in results['data']:
                    subdomain = f'{host["service"]["http"]["host"]}'
                    subdomains_list.append(subdomain)
            except:
                pass

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
    query = Quake(domain)
    subdomains = query.run()
    return subdomains
