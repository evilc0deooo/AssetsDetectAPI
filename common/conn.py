# -*- coding: utf-8 -*-

import requests
import random
import urllib3
from config import PROXY_URL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    'https': 'http://127.0.0.1:8080',
    'http': 'http://127.0.0.1:8080'
}

SET_PROXY = False

header_agents = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 '
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A ',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20120101 Firefox/33.0 '
]


def private_ip():
    """
    随机生成内网私有 IP address
    """
    private_ip_ranges = [
        (10, 0, 0, 0, 10, 255, 255, 255),
        (172, 16, 0, 0, 172, 31, 255, 255),
        (192, 168, 0, 0, 192, 168, 255, 255)
    ]

    start_range = random.choice(private_ip_ranges)
    start_ip = start_range[:4]
    end_ip = start_range[4:]
    ip_address = '.'.join(str(random.randint(start, end)) for start, end in zip(start_ip, end_ip))
    return ip_address


def http_req(url, method='get', **kwargs):
    kwargs.setdefault('verify', False)
    kwargs.setdefault('timeout', (10.1, 30.1))
    kwargs.setdefault('allow_redirects', False)

    headers = kwargs.get('headers', {})
    headers.setdefault('User-Agent', random.choice(header_agents))
    # 不允许缓存，每次请求都获取服务器上最新的资源
    headers.setdefault('Cache-Control', 'max-age=0')
    kwargs['headers'] = headers
    if PROXY_URL:
        proxies['https'] = PROXY_URL
        proxies['http'] = PROXY_URL
        kwargs['proxies'] = proxies

    conn = getattr(requests, method)(url, **kwargs)

    return conn
