# -*- coding: utf-8 -*-

import re
import dns.resolver
import tld
import thirdparty
from tld import get_tld
from common.baseinfo import BaseInfo
from config import BLACK_DOMAIN_PATH, BLACK_HEXIE_PATH, DNS_SERVER, FORBIDDEN_DOMAINS
from common.log_msg import logger

blackdomain_list = None
blackhexie_list = None


class DomainInfo(BaseInfo):
    def __init__(self, domain, record, type, ips):
        self.record_list = record
        self.domain = domain
        self.type = type
        self.ip_list = ips

    def __eq__(self, other):
        if isinstance(other, DomainInfo):
            if self.domain == other.domain:
                return True

    def __hash__(self):
        return hash(self.domain)

    def _dump_json(self):
        item = {
            'domain': self.domain,
            'record': self.record_list,
            'type': self.type,
            'ips': self.ip_list
        }
        return item


def match_subdomains(domain, html):
    """
    使用正则表达式匹配子域名
    """
    try:
        regexp = r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}' + domain.replace('.', r'\.')
        result = re.findall(regexp, html, re.I)
        if not result:
            return set()
        deal = map(lambda s: s.lower(), result)
        return set(deal)
    except:
        return set()


def get_title(body):
    """
    根据页面源码返回标题
    """
    result = ''
    title_patten = re.compile(rb'<title>([^<]{1,200})</title>', re.I)
    title = title_patten.findall(body)
    if len(title) > 0:
        try:
            result = title[0].decode('utf-8')
        except Exception:
            result = title[0].decode('gbk', errors='replace')
    return result.strip()


def get_headers(conn):
    """
    Response Headers
    """
    raw = conn.raw
    version = '1.1'
    if raw.version == 10:
        version = '1.0'

    first_line = f'HTTP/{version} {raw.status} {raw.reason}\n'

    headers = str(raw._fp.headers)

    headers = headers.strip()
    if not conn.headers.get('Content-Length'):
        headers = f'{headers}\nContent-Length: {len(conn.content)}'

    return first_line + headers


def domain_parsed(domain, fail_silently=True):
    """
    解析域名字段
    """
    domain = domain.strip()
    try:
        res = get_tld(domain, fix_protocol=True, as_object=True)
        item = {
            'subdomain': res.subdomain,
            'domain': res.domain,
            'fld': res.fld
        }
        return item
    except Exception as e:
        if not fail_silently:
            raise e


def get_fld(d):
    """
    获取域名的主域
    """
    res = domain_parsed(d)
    if res:
        return res['fld']


def check_domain_black(domain):
    """
    验证域名是否在黑名单
    """
    global blackdomain_list
    global blackhexie_list
    if blackdomain_list is None:
        with open(BLACK_DOMAIN_PATH) as f:
            blackdomain_list = f.readlines()

    for item in blackdomain_list:
        item = item.strip()
        if item and domain.endswith(item):
            return True

    if blackhexie_list is None:
        with open(BLACK_HEXIE_PATH) as f:
            blackhexie_list = f.readlines()

    try:
        for item in blackhexie_list:
            item = item.strip()
            _, _, subdomain = tld.parse_tld(domain, fix_protocol=True, fail_silently=True)
            # tld.parse_tld 解析拿到子域名
            if subdomain and item and item.strip() in subdomain:
                return True
    except Exception as e:
        logger.warning(f'error on: {domain}, {e}')
        return True

    return False


def is_valid_domain(domain):
    """
    验证有效域名
    """
    if '.' not in domain:
        return False

    invalid_chars = '!@#$%&*():_\\'
    for c in invalid_chars:
        if c in domain:
            return False

    # 不允许下发特殊二级域名
    if domain in ['com.cn', 'gov.cn', 'edu.cn']:
        return False

    if domain_parsed(domain):
        return True

    return False


def is_valid_fuzz_domain(domain):
    """
    是否存在模糊测试域名
    """
    if '{fuzz}' not in domain:
        return False

    domain = domain.replace('{fuzz}', '12fuzz12')
    parsed = domain_parsed(domain)
    if not parsed:
        return False

    if '12fuzz12' in parsed['fld']:
        return False

    return True


def is_forbidden_domain(domain):
    """
    域名后缀黑名单
    """
    for f_domain in FORBIDDEN_DOMAINS:
        if not f_domain:
            continue

        if domain.endswith('.' + f_domain):
            return True
        if domain == f_domain:
            return True

    return False


def read_file_to_list(file_path):
    """
    读取文本并转换为列表
    """
    try:
        with open(file_path, 'r') as file:
            content_list = file.readlines()
            content_list = [line.strip() for line in content_list]
        return content_list
    except FileNotFoundError:
        print(f'file not found: {file_path}')
        return []
    except Exception as e:
        print(f'an error occurred while reading the file {e}')
        return []


def get_ip(domain, dns_servers=True, log_flag=True):
    """
    获取 IP address
    """
    domain = domain.strip()
    ips = []
    try:
        # 设置DNS服务器列表
        resolver = dns.resolver.Resolver()
        dns_servers_list = read_file_to_list(DNS_SERVER)
        if dns_servers:
            resolver.nameservers = dns_servers_list
        answers = dns.resolver.resolve(domain, 'A')

        for rdata in answers:
            if rdata.address == '0.0.0.1':
                continue
            ips.append(rdata.address)
    except dns.resolver.NXDOMAIN as e:
        if log_flag:
            logger.info(f'{domain} {e}')

    except Exception as e:
        if log_flag:
            logger.warning(f'{domain} {e}')

    return ips


def get_cname(domain, log_flag=True):
    """
    获取域名 CNAME 解析记录
    """
    cnames = []
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cnames.append(str(rdata.target).strip(".").lower())
    except dns.resolver.NoAnswer as e:
        if log_flag:
            logger.debug(e)
    except Exception as e:
        logger.warning("{} {}".format(domain, e))

    return cnames


def not_found_domain_ips(base_domain):
    """
    用来判断是否是泛解析域名
    """
    _not_found_domain_ips = None  # 用来存放泛解析域名映射的IP

    if _not_found_domain_ips is None:
        fake_domain = 'atl' + thirdparty.random_choices(4) + '.' + base_domain
        _not_found_domain_ips = get_ip(fake_domain, log_flag=False)

        if _not_found_domain_ips:
            _not_found_domain_ips.extend(get_cname(fake_domain, log_flag=False))

        if _not_found_domain_ips:
            logger.info(f'not_found_domain_ips {fake_domain} {_not_found_domain_ips}')

    return _not_found_domain_ips
