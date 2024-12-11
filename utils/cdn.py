# -*- coding: utf-8 -*-

import json
import thirdparty
from IPy import IP
from config import CDN_JSON_PATH
from common.log_msg import logger

cdn_ip_cidr_list = []
cdn_cname_list = []
cdn_info = []


def _init_cdn_info():
    global cdn_ip_cidr_list, cdn_cname_list, cdn_info
    if not cdn_info:
        cdn_ip_cidr_list = []
        cdn_cname_list = []
        data = '\n'.join(thirdparty.load_file(CDN_JSON_PATH))
        cdn_info = json.loads(data)

        for item in cdn_info:
            cdn_cname_list.extend(item['cname_domain'])
            if item.get('ip_cidr'):
                cdn_ip_cidr_list.extend(item['ip_cidr'])


def _ip_in_cidr_list(ip):
    for item in cdn_ip_cidr_list:
        if IP(ip) in IP(item):
            return True


def _cname_in_cname_list(cname):
    for item in cdn_cname_list:
        if cname.endswith('.' + item):
            return True


def get_cdn_name_by_ip(ip):
    """
    通过 IP address 判断 CDN
    """
    try:
        _init_cdn_info()

        if not _ip_in_cidr_list(ip):
            return ''

        for item in cdn_info:
            if item.get('ip_cidr'):
                for ip_cidr in item['ip_cidr']:
                    if IP(ip) in IP(ip_cidr):
                        return item['name']

    except Exception as e:
        logger.warning(f'{e} {ip}')
        return ''


def _get_cdn_name_by_cname(cname):
    try:
        _init_cdn_info()
        if not _cname_in_cname_list(cname):
            return ''
        for item in cdn_info:
            for target in item['cname_domain']:
                if cname.endswith('.' + target):
                    return item['name']

    except Exception as e:
        logger.warning(f'{e} {cname}')
        return ''


def get_cdn_name_by_cname(cname):
    """
    通过 CNAME 判断 CDN
    """
    cdn_name = _get_cdn_name_by_cname(cname)
    check_list = ['gslb', 'dns', 'cache', 'cdn', 'cloudfront', 'ccgslb', 'edgekey', 'fastly', 'akamai']
    check_list.extend(['edgecast', 'azioncdn', 'cachefly', 'fpbns', 'footprint', 'llnwd'])
    check_list.extend(['telefonica', 'googlesyndication'])
    # 如果字典中的 CNAME 无法命中，则查看 check_list 中的关键字是否包含在 CNAME 中。
    if not cdn_name:
        for check in check_list:
            if check in cname:
                return 'CDN'

    return cdn_name
