# -*- coding: utf-8 -*-

import time
import thirdparty
from utils.domain import DomainInfo
from utils.domain import check_domain_black
from utils.domain import domain_parsed
from services.massdns import run as mass_dns
from services.resolver import run as resolver_domain
from config import DOMAIN_DICT_2W, DOMAIN_MAX_LEN
from common.log_msg import logger


class DomainBrute(object):
    def __init__(self, base_domain, word_file=DOMAIN_DICT_2W, wildcard_domain_ip=None):
        if wildcard_domain_ip is None:
            wildcard_domain_ip = []
        self.base_domain = base_domain
        self.base_domain_scope = '.' + base_domain.strip('.')
        self.words = thirdparty.load_file(word_file)
        self.brute_out = []
        self.resolver_map = {}
        self.domain_info_list = []
        self.domain_cnames = []
        self.brute_domain_map = {}  # 保存了通过 massdns 获取的结果
        self.wildcard_domain_ip = wildcard_domain_ip  # 保存获取的泛解析 IP

    def _brute_domain(self):
        self.brute_out = mass_dns(self.base_domain, self.words, self.wildcard_domain_ip)

    def _resolver(self):
        domains = []
        domain_cname_record = []  # CNAME 解析的域名集
        for x in self.brute_out:
            current_domain = x['domain'].lower()
            if not domain_parsed(current_domain):
                continue

            # 删除掉过长的子域名
            if len(current_domain) - len(self.base_domain) >= DOMAIN_MAX_LEN:
                continue

            # 屏蔽和谐域名和黑名单子域名
            if check_domain_black(current_domain):
                continue

            # 子域名集去重
            if current_domain not in domains:
                domains.append(current_domain)

            self.brute_domain_map[current_domain] = x['record']

            if x['type'] == 'CNAME':
                self.domain_cnames.append(current_domain)
                current_record_domain = x['record']

                # 丢弃非正确域名
                if not domain_parsed(current_record_domain):
                    continue

                # 屏蔽和谐 CNAME 域名在黑名单的子域名
                if check_domain_black(current_record_domain):
                    continue

                # 根据 CNAME 解析的域名去重
                if current_record_domain not in domain_cname_record:
                    domain_cname_record.append(current_record_domain)

        for domain in domain_cname_record:
            if not domain.endswith(self.base_domain_scope):
                continue
            if domain not in domains:
                domains.append(domain)

        start_time = time.time()
        logger.info(f'start resolver {self.base_domain} {len(domains)}')
        self.resolver_map = resolver_domain(domains)
        elapse = time.time() - start_time
        logger.info(f'end resolver {self.base_domain} result {len(self.resolver_map)}, elapse {elapse}')

    def run(self):
        """
        域名爆破
        """
        start_time = time.time()
        logger.info(f'start brute {self.base_domain} with dict {len(self.words)}')
        self._brute_domain()
        elapse = time.time() - start_time
        logger.info(f'end brute {self.base_domain}, result {len(self.brute_out)}, elapse {elapse}')

        self._resolver()

        for domain in self.resolver_map:
            ips = self.resolver_map[domain]
            if ips:
                if domain in self.domain_cnames:
                    item = {
                        'domain': domain,
                        'type': 'CNAME',
                        'record': [self.brute_domain_map[domain]],
                        'ips': ips
                    }
                else:
                    item = {
                        'domain': domain,
                        'type': 'A',
                        'record': ips,
                        'ips': ips
                    }
                self.domain_info_list.append(DomainInfo(**item))

        self.domain_info_list = list(set(self.domain_info_list))
        return self.domain_info_list


def run(base_domain, word_file=DOMAIN_DICT_2W, wildcard_domain_ip=None):
    """
    类统一调用入口
    """
    if wildcard_domain_ip is None:
        wildcard_domain_ip = []

    b = DomainBrute(base_domain, word_file, wildcard_domain_ip)
    return b.run()
