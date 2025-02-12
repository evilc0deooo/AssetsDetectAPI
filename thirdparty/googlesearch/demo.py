# -*- coding: utf-8 -*-

from thirdparty.googlesearch import search
from urllib.parse import urlparse


def google_spider(domain):
    key = f'site:{domain}'

    for each_result in search(key, stop=3):
        parse_ret = urlparse(each_result)
        print(each_result, parse_ret)
        if domain in parse_ret.netloc:
            print(parse_ret.netloc)


if __name__ == '__main__':
    google_spider('baidu.com')
