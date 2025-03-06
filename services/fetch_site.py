# -*- coding: utf-8 -*-

import time
import binascii
import mmh3
import re
from pyquery import PyQuery
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from services.auto_tag import run as auto_tag
from common.base_thread import BaseThread
from utils.domain import get_ip, domain_parsed, get_headers, get_title
from utils.fingerprint import FINGERPRINT, fetch_fingerprint
from common.conn import http_req
from common.log_msg import logger


class FetchFavicon(object):
    def __init__(self, url):
        self.url = url
        self.favicon_url = None
        pass

    def build_result(self, data):
        result = {
            'data': data,
            'url': self.favicon_url,
            'hash': mmh3.hash(data)
        }
        return result

    def run(self):
        result = {}
        try:
            favicon_url = urljoin(self.url, '/favicon.ico')
            data = self.get_favicon_data(favicon_url)
            if data:
                self.favicon_url = favicon_url
                return self.build_result(data)

            favicon_url = self.find_icon_url_from_html()
            if not favicon_url:
                return result
            data = self.get_favicon_data(favicon_url)
            if data:
                self.favicon_url = favicon_url
                return self.build_result(data)

        except Exception as e:
            logger.warning(f'error on {self.url} {e}')

        return result

    def get_favicon_data(self, favicon_url):
        conn = http_req(favicon_url)
        if conn.status_code != 200:
            return

        if len(conn.content) <= 80:
            logger.debug('favicon content len lt 100')
            return

        if 'image' in conn.headers.get('Content-Type', ''):
            data = self.encode_bas64_lines(conn.content)
            return data

    @staticmethod
    def encode_bas64_lines(s):
        """Encode a string into multiple lines of base-64 data."""
        MAXLINESIZE = 76  # Excluding the CRLF
        MAXBINSIZE = (MAXLINESIZE // 4) * 3
        pieces = []
        for i in range(0, len(s), MAXBINSIZE):
            chunk = s[i: i + MAXBINSIZE]
            pieces.append(bytes.decode(binascii.b2a_base64(chunk)))
        return ''.join(pieces)

    def find_icon_url_from_html(self):
        conn = http_req(self.url)
        if b"<link" not in conn.content:
            return
        d = PyQuery(conn.content)
        links = d('link').items()
        icon_link_list = []
        for link in links:
            if link.attr('href') and 'icon' in link.attr('rel'):
                icon_link_list.append(link)

        for link in icon_link_list:
            if 'shortcut' in link:
                return urljoin(self.url, link.attr('href'))

        if icon_link_list:
            return urljoin(self.url, icon_link_list[0].attr('href'))


def fetch_favicon(url):
    """
    获取站点 favicon 图标信息
    """
    f = FetchFavicon(url)
    return f.run()


class FetchSite(BaseThread):
    def __init__(self, sites, concurrency=6, http_timeout=None):
        super().__init__(sites, concurrency)
        self.site_info_list = []
        self.http_timeout = http_timeout
        if http_timeout is None:
            self.http_timeout = (10.1, 30.1)

    def fetch_fingerprint(self, item, content):
        favicon_hash = item['favicon'].get('hash', 0)
        result = fetch_fingerprint(content=content, headers=item['headers'],
                                   title=item['title'], favicon_hash=favicon_hash,
                                   finger_list=FINGERPRINT)

        finger_list = []

        for name in result:
            finger_name = name.lower()
            finger_item = {
                'icon': 'default.png',
                'name': finger_name,
                'confidence': '80',
                'version': '',
                'website': '',
                'categories': []
            }

            # 对指纹名称进行去重
            if finger_item not in finger_list:
                finger_list.append(finger_item)

        if finger_list:
            item['finger'] = finger_list

    def work(self, site):
        if '://' not in site:
            site = 'http://' + site
        hostname = urlparse(site).netloc
        conn = http_req(site, timeout=self.http_timeout)
        # 遇到 ip 白名单拦截尝试使用 XFF 伪造进行绕过处理
        if conn.status_code == 403 and b'Because of your IP You Do Not Have The Permission To Access This Page' in conn.content:
            headers = {
                'X-Forwarded-For': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1'
            }

            conn = http_req(site, headers=headers, timeout=self.http_timeout, allow_redirects=True)

        # 实战中遇到一些 403 页面但存在 url 跳转体，进行一些兼容处理
        elif conn.status_code == 403 and b'window.location' in conn.content:
            site_url = ''
            soup = BeautifulSoup(conn.text, 'html.parser')
            meta_refresh = soup.find('meta', {'http-equiv': 'refresh'})
            if meta_refresh:
                script_tags = soup.find_all('script')
                patterns = [
                    r'window\.location\.replace\(["\']([^"\']+)["\']\);',
                    r'window\.location\.href\s*=\s*["\']([^"\']+)["\'];',
                    r'window\.location\.assign\(["\']([^"\']+)["\']\);',
                    r'document\.location\s*=\s*["\']([^"\']+)["\'];',
                    r'window\.navigate\(["\']([^"\']+)["\']\);'
                ]
                for script in script_tags:
                    script_text = script.get_text()
                    for pattern in patterns:
                        match = re.search(pattern, script_text)
                        if match:
                            redirect_url = match.group(1)
                            if 'http' not in redirect_url:
                                site_url = urljoin(site, redirect_url)
                            else:
                                site_url = redirect_url
                            break
                    else:
                        continue
                    break

            if site_url:
                conn = http_req(site_url, timeout=self.http_timeout, allow_redirects=True)

        item = {
            'site': site,
            'hostname': hostname,
            'ip': '',
            'title': get_title(conn.content),
            'status': conn.status_code,
            'headers': get_headers(conn),
            'http_server': conn.headers.get('Server', ''),
            'body_length': len(conn.content),
            'finger': [],
            'favicon': fetch_favicon(site)
        }

        self.fetch_fingerprint(item, content=conn.content)
        _domain_parsed = domain_parsed(hostname)
        if _domain_parsed:
            item['fld'] = _domain_parsed['fld']
            ips = get_ip(hostname)
            if ips:
                item['ip'] = ips[0]
        else:
            item['ip'] = hostname

        self.site_info_list.append(item)
        if conn.status_code == 301 or conn.status_code == 302:
            url_302 = urljoin(site, conn.headers.get('Location', ''))
            # 防御性编程
            if len(url_302) > 100:
                return

            if url_302 != site and url_302.startswith(site):
                site_path = urlparse(site).path.strip('/')
                url_302_path = urlparse(url_302).path.strip('/')
                if len(site_path) > 5 and url_302_path.endswith(site_path):
                    return
                self.work(url_302)

    def run(self):
        t1 = time.time()
        logger.info(f'start fetch site {len(self.targets)}')
        self._run()
        elapse = time.time() - t1
        logger.info(f'end fetch site elapse {elapse}')

        # 对站点信息自动打标签
        auto_tag(self.site_info_list)

        return self.site_info_list


def run(sites, concurrency=15, http_timeout=None):
    """
    类统一调用入口
    """
    f = FetchSite(sites, concurrency=concurrency, http_timeout=http_timeout)
    return f.run()
