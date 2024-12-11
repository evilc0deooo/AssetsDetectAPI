# -*- coding: utf-8 -*-

import re
import time
import tld
import random
import thirdparty
from collections import Counter
from thirdparty import MASSDNS_BIN, MASSDNS_ARM_BIN, TMP_PATH
from services.massdns import MassDNS
from services.resolver import DomainInfo
from utils.domain import check_domain_black
from config import DNS_SERVER, ALT_DNS_DICT_PATH, ALT_DNS_CONCURRENT
from common.log_msg import logger

NUM_COUNT = 4


#  FROM: https://github.com/ProjectAnte/dnsgen/blob/master/dnsgen/dnsgen.py

class DnsGen(object):
    def __init__(self, subdomains, words, base_domain=None):
        self.subdomains = subdomains
        self.base_domain = base_domain
        self.words = words

    def partiate_domain(self, domain):
        """
        Split domain base on subdomain levels.
        TLD is taken as one part, regardless of its levels (.co.uk, .com, ...)
        """

        # test.1.foo.example.com -> [test, 1, foo, example.com]
        # test.2.foo.example.com.cn -> [test, 2, foo, example.com.cn]
        # test.example.co.uk -> [test, example.co.uk]
        if self.base_domain:
            subdomain = re.sub(re.escape("." + self.base_domain) + "$", '', domain)
            return subdomain.split(".") + [self.base_domain]

        ext = tld.get_tld(domain.lower(), fail_silently=True, as_object=True, fix_protocol=True)
        base_domain = "{}.{}".format(ext.domain, ext.suffix)

        parts = (ext.subdomain.split('.') + [base_domain])

        return [p for p in parts if p]

    def insert_word_every_index(self, parts):
        """
        Create new subdomain levels by inserting the words between existing levels
        """

        # test.1.foo.example.com -> WORD.test.1.foo.example.com, test.WORD.1.foo.example.com,
        #                           test.1.WORD.foo.example.com, test.1.foo.WORD.example.com, ...

        domains = []

        for w in self.words:
            for i in range(len(parts)):
                if i + 1 == len(parts):
                    break

                if w in parts[:-1]:
                    continue

                tmp_parts = parts[:-1]
                tmp_parts.insert(i, w)
                domains.append('{}.{}'.format('.'.join(tmp_parts), parts[-1]))

        return domains

    @staticmethod
    def insert_num_every_index(parts):
        """
        Create new subdomain levels by inserting the numbers between existing levels
        """

        # foo.test.example.com ->   foo1.test.example.com, foo.test1.example.com,
        #                            ...

        domains = []

        for num in range(NUM_COUNT):
            for i in range(len(parts[:-1])):
                if num == 0:
                    continue
                # single digit
                tmp_parts = parts[:-1]
                tmp_parts[i] = '{}{}'.format(tmp_parts[i], num)
                domains.append('{}.{}'.format('.'.join(tmp_parts), '.'.join(parts[-1:])))

        return domains

    def prepend_word_every_index(self, parts):
        """
        On every subdomain level, prepend existing content with `WORD` and `WORD-`
        """

        # test.1.foo.example.com -> WORDtest.1.foo.example.com, test.WORD1.foo.example.com,
        #                           test.1.WORDfoo.example.com, WORD-test.1.foo.example.com,
        #                           test.WORD-1.foo.example.com, test.1.WORD-foo.example.com, ...

        domains = []

        for w in self.words:
            for i in range(len(parts[:-1])):
                # prepend normal
                if w in parts[:-1]:
                    continue

                tmp_parts = parts[:-1]
                tmp_parts[i] = '{}{}'.format(w, tmp_parts[i])
                domains.append('{}.{}'.format('.'.join(tmp_parts), parts[-1]))

                # prepend with dash
                tmp_parts = parts[:-1]
                tmp_parts[i] = '{}-{}'.format(w, tmp_parts[i])
                domains.append('{}.{}'.format('.'.join(tmp_parts), parts[-1]))

        return domains

    def append_word_every_index(self, parts):
        """
        On every subdomain level, append existing content with `WORD` and `WORD-`
        """

        # test.1.foo.example.com -> testWORD.1.foo.example.com, test.1WORD.foo.example.com,
        #                           test.1.fooWORD.example.com, test-WORD.1.foo.example.com,
        #                           test.1-WORD.foo.example.com, test.1.foo-WORD.example.com, ...

        domains = []

        for w in self.words:
            for i in range(len(parts[:-1])):
                # append normal
                if w in parts[:-1]:
                    continue

                tmp_parts = parts[:-1]
                tmp_parts[i] = '{}{}'.format(tmp_parts[i], w)
                domains.append('{}.{}'.format('.'.join(tmp_parts), '.'.join(parts[-1:])))

                # append with dash
                tmp_parts = parts[:-1]
                tmp_parts[i] = '{}-{}'.format(tmp_parts[i], w)
                domains.append('{}.{}'.format('.'.join(tmp_parts), '.'.join(parts[-1:])))

        return domains

    def replace_word_with_word(self, parts):
        """
        If word longer than 3 is found in existing subdomain, replace it with other words from the dictionary
        """

        # WORD1.1.foo.example.com -> WORD2.1.foo.example.com, WORD3.1.foo.example.com,
        #                            WORD4.1.foo.example.com, ...

        domains = []

        for w in self.words:
            if len(w) <= 3:
                continue

            if w in '.'.join(parts[:-1]):
                for w_alt in self.words:
                    if w == w_alt:
                        continue

                    if w in parts[:-1]:
                        continue
                    domains.append('{}.{}'.format('.'.join(parts[:-1]).replace(w, w_alt), '.'.join(parts[-1:])))

        return domains

    def run(self):
        for domain in set(self.subdomains):
            parts = self.partiate_domain(domain)
            permutations = []
            permutations += self.insert_word_every_index(parts)
            permutations += self.insert_num_every_index(parts)
            permutations += self.prepend_word_every_index(parts)
            permutations += self.append_word_every_index(parts)
            permutations += self.replace_word_with_word(parts)

            for perm in permutations:
                yield perm


class AltDNS(object):
    def __init__(self, domain_info_list, base_domain, wildcard_domain_ip=None):
        self.domain_info_list = domain_info_list
        self.base_domain = base_domain
        inner_dicts = 'test adm admin api app beta demo dev front int internal intra ops pre pro prod qa sit staff stage test uat ceshi'
        self.words = inner_dicts.split()

        self.domains = []
        self.subdomains = []
        if wildcard_domain_ip is None:
            wildcard_domain_ip = []

        self.wildcard_domain_ip = wildcard_domain_ip

    @staticmethod
    def _load_dict():
        """
        加载字典
        """
        w = set()
        for x in thirdparty.load_file(ALT_DNS_DICT_PATH):
            x = x.strip()
            if x:
                w.add(x)

        return list(w)

    def _fetch_domains(self):
        """
        遍历域名
        """
        base_len = len(self.base_domain)
        for item in self.domain_info_list:
            if not item.domain.endswith('.' + self.base_domain):
                continue

            # 剔除黑名单域名
            if check_domain_black('a.' + item.domain):
                continue

            self.domains.append(item.domain)
            subdomain = item.domain[:- (base_len + 1)]
            if '.' in subdomain:
                # 仅保留子域名部分，剔除主域名 www.domain.com ——> www
                self.subdomains.append(subdomain.split('.')[-1])

        random.shuffle(self.subdomains)

        most_cnt = 50
        # 如果子域名数量小于 800 则加载 altdns_wordlist.txt 字典
        if len(self.domains) < 800:
            most_cnt = 30
            self.words.extend(self._load_dict())
        sub_dicts = list(dict(Counter(self.subdomains).most_common(most_cnt)).keys())
        self.words.extend(sub_dicts)
        self.words = list(set(self.words))

    def run(self):
        t1 = time.time()
        self._fetch_domains()
        domains = DnsGen(set(self.domains), self.words, base_domain=self.base_domain).run()
        domains = list(set(domains))
        logger.info(f'start alt_dns:{self.base_domain} words:{len(domains)} wildcard_record:{self.wildcard_domain_ip}')

        architecture = thirdparty.get_architecture()
        if architecture == 'ARM':  # 只针对 Apple M1 芯片进行判断
            mass = MassDNS(domains, mass_dns_bin=MASSDNS_ARM_BIN, dns_server=DNS_SERVER, tmp_dir=TMP_PATH,
                           wildcard_domain_ip=self.wildcard_domain_ip,
                           concurrent=ALT_DNS_CONCURRENT)
        else:
            mass = MassDNS(domains, mass_dns_bin=MASSDNS_BIN, dns_server=DNS_SERVER, tmp_dir=TMP_PATH,
                           wildcard_domain_ip=self.wildcard_domain_ip,
                           concurrent=ALT_DNS_CONCURRENT)
        raw_domains_info = mass.run()

        # 解决泛解析的问题
        domains_info = []
        records = [x['record'] for x in raw_domains_info]
        records_count = Counter(records)

        for info in raw_domains_info:
            # 使用 Counter 类来计算 record 值在数据集中的出现次数，如果出现次数超过 15 次，将其判定为泛解析.
            if records_count[info['record']] >= 15:
                continue
            domains_info.append(info)
        elapse = time.time() - t1
        logger.info(f'end alt_dns result {len(domains_info)}, elapse {elapse}')
        return domains_info


def run(domain_info_list, base_domain=None, wildcard_domain_ip=None):
    """
    类统一调用入口
    """
    if len(domain_info_list) == 0:
        return []

    a = AltDNS(domain_info_list, base_domain, wildcard_domain_ip=wildcard_domain_ip)
    domains_info = a.run()

    return domains_info
