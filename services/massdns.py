# -*- coding: utf-8 -*-

import os
import thirdparty
from thirdparty import MASSDNS_BIN, MASSDNS_ARM_BIN, MASSDNS_ARCH_BIN, TMP_PATH
from config import DNS_SERVER, DOMAIN_DICT_2W, DOMAIN_BRUTE_CONCURRENT
from common.log_msg import logger


class MassDNS(object):
    def __init__(self, domains=None, mass_dns_bin=None, dns_server=None, tmp_dir=None, wildcard_domain_ip=None,
                 concurrent=0):

        if wildcard_domain_ip is None:
            wildcard_domain_ip = []

        if concurrent == 0:
            concurrent = 100

        self.domains = domains
        self.tmp_dir = tmp_dir
        self.dns_server = dns_server
        self.domain_gen_output_path = os.path.join(self.tmp_dir, f'domain_gen_{thirdparty.random_choices()}')
        self.mass_dns_output_path = os.path.join(self.tmp_dir, f'mass_dns_{thirdparty.random_choices()}')
        self.mass_dns_bin = mass_dns_bin
        self.wildcard_domain_ip = wildcard_domain_ip
        self.concurrent = concurrent

        os.chmod(self.mass_dns_bin, 0o777)

    def domain_write(self):
        """
        将域名写到文件
        """
        count = 0
        with open(self.domain_gen_output_path, 'w') as f:
            for domain in self.domains:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + '\n')
                count += 1

        logger.info(f'massdns domains dict {count}')

    def mass_dns(self):
        """
        域名爆破
        """
        command = [self.mass_dns_bin, '-q',
                   f'-r {self.dns_server}',
                   '-o S',
                   f'-w {self.mass_dns_output_path}',
                   f'-s {self.concurrent}',
                   self.domain_gen_output_path,
                   '--root'
                   ]

        thirdparty.exec_system(command, timeout=5 * 24 * 60 * 60)

    def parse_mass_dns_output(self):
        output = []
        with open(self.mass_dns_output_path, 'r+', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                data = line.split(' ')
                if len(data) != 3:
                    continue
                domain, _type, record = data
                record = record.strip().strip('.')

                # 泛解析域名 ip 直接过滤掉
                if record in self.wildcard_domain_ip:
                    continue

                item = {
                    'domain': domain.strip('.'),
                    'type': _type,
                    'record': record
                }
                output.append(item)

        self._delete_file()
        return output

    def _delete_file(self):
        try:
            os.unlink(self.domain_gen_output_path)
            os.unlink(self.mass_dns_output_path)
        except Exception as e:
            logger.warning(e)

    def run(self):
        self.domain_write()
        self.mass_dns()
        output = self.parse_mass_dns_output()
        return output


def run(domain, words=None, wildcard_domain_ip=None):
    """
    类统一调用入口
    """
    if wildcard_domain_ip is None:
        wildcard_domain_ip = []

    if words is None:
        words = thirdparty.load_file(DOMAIN_DICT_2W)

    domains = []
    is_fuzz_domain = '{fuzz}' in domain
    for word in words:
        word = word.strip()
        if word:
            if is_fuzz_domain:
                domains.append(domain.replace('{fuzz}', word))
            else:
                domains.append(f'{word}.{domain}')

    if not is_fuzz_domain:
        domains.append(domain)

    logger.info(f'start brute:{domain} words:{len(domains)} wildcard_record:{",".join(wildcard_domain_ip)}')

    architecture = thirdparty.get_architecture()
    if architecture == 'ARM':  # 针对 Apple M1 芯片进行判断
        mass = MassDNS(domains, mass_dns_bin=MASSDNS_ARM_BIN, dns_server=DNS_SERVER, tmp_dir=TMP_PATH,
                       wildcard_domain_ip=wildcard_domain_ip,
                       concurrent=DOMAIN_BRUTE_CONCURRENT)
    elif architecture == "ARCH":
        mass = MassDNS(domains, mass_dns_bin=MASSDNS_ARCH_BIN, dns_server=DNS_SERVER, tmp_dir=TMP_PATH,
                       wildcard_domain_ip=wildcard_domain_ip,
                       concurrent=DOMAIN_BRUTE_CONCURRENT)
    else:
        mass = MassDNS(domains, mass_dns_bin=MASSDNS_BIN, dns_server=DNS_SERVER, tmp_dir=TMP_PATH,
                       wildcard_domain_ip=wildcard_domain_ip,
                       concurrent=DOMAIN_BRUTE_CONCURRENT)

    return mass.run()
