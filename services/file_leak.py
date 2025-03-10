# -*- coding: utf-8 -*-

import difflib
import itertools
import os
import time
import urllib3
import thirdparty
from typing import List
from urllib.parse import urlparse, urljoin
from tld import get_tld
from config import FILE_LEAK_TEST_DICT
from common.base_thread import BaseThread
from common.conn import http_req
from utils.domain import get_title
from common.log_msg import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

bool_ratio = 0.95
concurrency_count = 4


class URL(object):
    def __init__(self, url, payload):
        self.url = url
        self.payload = payload
        self._scope = None
        self._path = None

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        if isinstance(other, URL):
            return self.url == other.url
        else:
            return False

    def __hash__(self):
        return hash(self.url)

    def __str__(self):
        return self.url

    def __repr__(self):
        return '<URL> ' + self.__str__()

    def __lt__(self, other):
        return self.url < other.url

    def __gt__(self, other):
        return self.url > other.url

    @property
    def scope(self) -> str:
        if self._scope is None:
            parse = urlparse(self.url)
            scope = f'{parse.scheme}://{parse.netloc}'
            self._scope = scope

        return self._scope

    @property
    def path(self) -> str:
        if self._path is None:
            parse = urlparse(self.url)
            self._path = parse.path

        return self._path


class HTTPReq(object):
    def __init__(self, url: URL, read_timeout=60, max_length=50 * 1024):
        self.url = url
        self.read_timeout = read_timeout
        self.max_length = max_length
        self.conn = None
        self.status_code = None
        self.content = None

    def req(self):
        content = b''
        try:
            conn = http_req(self.url.url, 'get', timeout=(7, 10), stream=True)
        except:
            self.status_code = 404
            self.content = b''
        # 如果没有异常继续执行 else 代码块
        else:
            self.conn = conn
            start_time = time.time()
            for data in conn.iter_content(chunk_size=512):
                if time.time() - start_time >= self.read_timeout:
                    break
                content += data
                if len(content) >= int(self.max_length):
                    break

            self.status_code = conn.status_code
            self.content = content[:self.max_length]

            content_len = self.conn.headers.get('Content-Length', len(self.content))
            self.conn.headers['Content-Length'] = content_len

            conn.close()

            return self.status_code, self.content


class Page(object):
    def __init__(self, req: HTTPReq):
        self.raw_req = req
        self.url = req.url
        self.content = req.content
        self.body_length = len(self.content)
        self.times = 0
        self.status_code = req.status_code
        self._title = None
        self._location_url = None
        self._is_back_up_path = None
        self._is_back_up_page = None
        self.back_up_suffix_list = ['.tar', '.tar.gz', '.zip', '.rar', '.7z', '.bz2', '.gz', '.war']

    def __eq__(self, other):
        if isinstance(other, Page):
            if self.status_code != other.status_code:
                return False

            if self.is_302() and other.is_302():
                self_new_url = self.location_url
                other_new_url = other.location_url

                self_new_url = urljoin(self.url.url, self_new_url)
                other_new_url = urljoin(other.url.url, other_new_url)

                if self_new_url.endswith(self.url.payload + '/'):
                    if other_new_url.endswith(other.url.payload + '/'):
                        if not self.url.payload.endswith('/') and not other.url.payload.endswith('/'):
                            return False

                self_new_path = urlparse(self_new_url).path
                other_new_path = urlparse(other_new_url).path

                path1 = self_new_path.replace(self.url.payload, '$AAAA$')
                path2 = other_new_path.replace(other.url.payload, '$AAAA$')

                if urlparse(self_new_url).netloc == urlparse(other_new_url).netloc:
                    if path1 == path2 and self_new_path.endswith('$AAAA$/'):
                        if not self.url.payload.endswith('/') and not other.url.payload.endswith('/'):
                            return False

                if path1 == path2:
                    self.times += 1
                    return True
                else:
                    return False

            self_content = self.content.replace(self.url.payload.encode(), b'')
            other_content = other.content.replace(other.url.payload.encode(), b'')

            if abs(len(self_content) - len(other_content)) <= 5:
                self.times += 1
                return True

            min_len_content = min(len(self_content), len(other_content))
            if abs(len(self_content) - len(other_content)) >= max(500, int(min_len_content * 0.1)):
                return False

            if len(self.title) > 2 and self.title == other.title:
                return True

            quick_ratio = difflib.SequenceMatcher(None, self_content, other_content).quick_ratio()
            if quick_ratio >= bool_ratio:
                self.times += 1
                return True
            else:
                return False

        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        p = urlparse(self.url.url)
        return hash(p.scheme + '://' + p.netloc)

    @property
    def location_url(self) -> str:
        if self._location_url is None:
            location = self.raw_req.conn.headers.get('Location', '')
            new_url = urljoin(self.url.url, location)
            self._location_url = new_url.split('?')[0]

        return self._location_url

    def is_302(self):
        return self.status_code in [301, 302, 307, 308]

    @property
    def title(self) -> str:
        if self._title is None:
            self._title = get_title(self.content).strip()

        return self._title

    @property
    def is_backup_path(self) -> bool:
        if self._is_back_up_path is None:
            for suffix in self.back_up_suffix_list:
                if self.url.path.endswith(suffix):
                    self._is_back_up_path = True
                    return self._is_back_up_path

            self._is_back_up_path = False

        return self._is_back_up_path

    @property
    def is_backup_page(self) -> bool:
        if self._is_back_up_page is None:
            content_type = self.raw_req.conn.headers.get('Content-Type', '')
            if 'application' in content_type.lower():
                self._is_back_up_page = True
            else:
                self._is_back_up_page = False

        return self._is_back_up_page

    def __str__(self):
        msg = f'[{self.status_code}][{self.title}][{len(self.content)}]{self.url}'
        return msg

    def __repr__(self):
        return '<Page> ' + self.__str__()

    def dump_json(self):
        item = {
            'title': self.title,
            'url': str(self.url),
            'content_length': len(self.content),
            'status_code': self.status_code,
        }

        return item


class FileLeak(BaseThread):
    def __init__(self, target, urls, concurrency=4):
        super().__init__(urls, concurrency=concurrency)
        self.target = target.rstrip('/') + '/'
        self.urls = urls
        self.path_404 = 'not_found_2222_111'
        self.page404_set = set()
        self.page200_set = set()
        self.page200_code_list = [200, 301, 302, 500]
        self.page404_title = ['404', '不存在', '错误', '403', '禁止访问', '请求含有不合法的参数', '找不到']
        self.page404_title.extend(['网络防火墙', '访问拦截', '由于安全原因JSP功能默认关闭'])
        self.page404_content = [b'<script>document.getElementById("a-link").click();</script>', b'Not found']
        self.waf_content = [b'<h1 data-translate="block_headline">Sorry, you have been blocked</h1>', b'gostr=/waf.123.123;locaid=d001;']
        self.waf_content.extend([b'alicdn.com/sd/punish/waf_block.html'])
        self.location404 = ['/auth/login/', 'error.html']
        self.page_all = []
        self.error_times = 0
        self.record_page = False
        self.skip_302 = False
        self.location_404_url = set()

    def check_waf_in_text(self, response_content):
        """
        判断 WAF 特征列表的元素是否在响应体中
        """
        for waf_key in self.waf_content:
            if waf_key in response_content:
                return True
        return False

    def work(self, url):
        if self.error_times >= 15:
            return

        req = self.http_req(url)

        # 添加识别 WAF 功能,
        waf_check = self.check_waf_in_text(req.content)
        if waf_check:  # 触发 WAF 拦截直接停止后续扫描
            return

        page = Page(req)
        if self.record_page:
            self.page_all.append(page)

        if self.is_404_page(page):
            self.page404_set.add(page)
            return

        if page not in self.page404_set:
            self.page200_set.add(page)

    def build_404_page(self):
        url_404 = URL(self.target + self.path_404, self.path_404)
        page_404 = Page(self.http_req(url_404))
        self.page404_set.add(page_404)
        if self.record_page:
            self.page_all.append(page_404)

        if page_404.is_302():
            self.location_404_url.add(page_404.location_url)

        if page_404.is_302() and page_404.location_url.endswith(page_404.url.payload + '/'):
            self.skip_302 = True

    def run(self):
        t1 = time.time()
        logger.info(f'start file leak {len(self.targets)}.')

        self.build_404_page()
        self._run()
        self.check_page_200()

        elapse = time.time() - t1

        logger.info(f'end file leak elapse {elapse}.')

        return self.page200_set

    def http_req(self, url: URL):
        try:
            req = HTTPReq(url)
            req.req()
            return req
        except Exception as e:
            logger.warning(f'error on {e}')
            self.error_times += 1
            raise e

    def is_404_page(self, page: Page):
        if page.status_code not in self.page200_code_list:
            return True

        if page.is_backup_path:
            if not page.is_backup_page:
                return True

        for title in self.page404_title:
            if title in page.title:
                return True

        for content in self.page404_content:
            if content in page.content:
                return True

        if '/.' in page.url.url and page.status_code == 200:
            if len(page.content) == 0:
                return True

        if page.is_302():
            for location_404 in self.location404:
                if location_404 in page.location_url:
                    return True

            if not page.location_url.endswith(page.url.payload + '/'):
                self.location_404_url.add(page.location_url)
                return True

            return page.location_url in self.location_404_url

        return False

    def check_page_200(self):
        for page in self.page200_set:
            if page in self.page404_set:
                continue

            if self.skip_302:
                self.page404_set.add(page)
                continue

            url_404_list = self.gen_check_url(page.url)

            for url_404 in url_404_list:
                page_404 = Page(self.http_req(url_404))
                self.page404_set.add(page_404)

                if page_404.is_302() and page_404.location_url.endswith(page_404.url.payload + '/'):
                    self.page404_set.add(page)
                    self.skip_302 = True

        self.page200_set -= self.page404_set

    @staticmethod
    def gen_check_url(url: URL):
        payload = url.payload
        if url.path in url.scope:
            check_url = url.url + '1337'
        else:
            check_url = url.url.replace(url.path, url.path + '1337')
        end_check_url = URL(check_url, payload + '1337')

        payload_list = ['..', '?', 'etc/passwd']
        for p in payload_list:
            if p in payload:
                check_url = url.url.replace(p, p + 'a1337')
                payload = payload.replace(p, p + 'a1337')
                return [URL(check_url, payload)]

        if '.' in url.path and '.' in payload:
            path = url.path.replace('.', 'a1337.')
            check_url = f'{url.scope}{path}'
            payload = payload.replace('.', 'a1337.')
            return [URL(check_url, payload), end_check_url]

        if url.path.endswith('/'):
            path = url.path[:-1] + 'a1337/'
            check_url = f'{url.scope}{path}'
            payload = payload + 'a1337/'
            return [URL(check_url, payload)]

        return [end_check_url]


def normal_url(url):
    scheme_map = {
        'http': 80,
        'https': 443
    }
    o = urlparse(url)

    scheme = o.scheme
    hostname = o.hostname
    path = o.path

    if scheme not in scheme_map:
        return ''

    if o.path == '':
        path = '/'

    if o.port == scheme_map[o.scheme] or o.port is None:
        ret_url = f'{scheme}://{hostname}{path}'

    else:
        ret_url = f'{scheme}://{hostname}:{o.port}{path}'

    if o.query:
        ret_url = ret_url + '?' + o.query

    return ret_url


class GenBackDicts:
    def __init__(self, url):
        self.target = normal_url(url)
        self.suffixs = ['.tar', '.tar.gz', '.zip', '.rar', '.7z', '.bz2', '.gz', '_bak.rar', '.war', '2022.rar', '2022.zip', '2023.rar', '2024.zip', '2024.rar', '2025.zip', '2025.rar', '2025.zip']
        self.backup_path_deep = 7
        self.dymaic_dicts_deep = 5
        self.path = urlparse(self.target).path

    def gen_dict_from_domain(self):
        result = []
        res = get_tld(self.target, as_object=True, fail_silently=True)
        if res:
            result = [x for x in [str(res.parsed_url.netloc).split(':')[0], res.fld, res.subdomain,
                                  res.domain] + res.subdomain.split('.') if x != '']

        return set(result)

    def gen_backup_dicts(self, nemes):
        out = []
        items = itertools.product(nemes, self.suffixs)
        for x in items:
            out.append(''.join(x))
        return out

    def gen_dict_from_path(self):
        out = []
        dirs = os.path.dirname(self.path).split('/')
        if len(dirs) > 1 and dirs[-1]:
            out = self.gen_backup_dicts([dirs[-1]])
        return out

    def gen(self):
        ret = set()
        names = self.gen_dict_from_domain()

        for x in self.gen_backup_dicts(names):
            ret.add(URL(urljoin(self.target, x), x))

        for x in self.gen_dict_from_path():
            ret.add(URL(urljoin(self.target, x), x))
            ret.add(URL(urljoin(self.target, './../' + x), x))

        return ret


class GenURL(object):
    def __init__(self, target, dicts):
        self.target = normal_url(target).split('?')[0]
        self.dicts = set(dicts)
        self.urls = set()

    def build_urls(self):
        target = os.path.dirname(self.target)
        for d in self.dicts:
            # fix: 过滤空路径
            if d == '\n':
                continue
            u = URL(f'{target}/{d.strip()}', d.strip())
            self.urls.add(u)

    def gen(self, flag=True):
        if urlparse(self.target).path == '/':
            self.dicts |= GenBackDicts(self.target).gen_dict_from_domain()

        self.build_urls()
        if flag:
            self.urls |= GenBackDicts(self.target).gen()

        return self.urls


def run(targets, dicts, gen_dict=True) -> List[Page]:
    """
    类统一调用入口
    """
    all_gen_url = set()
    map_url = dict()
    for site in targets:
        site = normal_url(site.strip())
        if not site:
            continue

        map_url[URL(site, '').scope] = set()
        a = GenURL(site, dicts)
        all_gen_url |= a.gen(gen_dict)

    for url in all_gen_url:
        map_url[url.scope].add(url)

    cnt = 0
    ret = []
    for target in map_url:
        cnt += 1
        try:
            f = FileLeak(target, map_url[target], concurrency_count)
            page_data = f.run()
            for _page in page_data:
                logger.info(f'found => {_page}')

            ret.extend(page_data)
        except Exception as e:
            logger.warning(f'error on {target}, {e}')

    return ret


if __name__ == '__main__':
    dicts = thirdparty.load_file(FILE_LEAK_TEST_DICT)

    url_list = ['https://toodpe.aliwork.com/']
    pages = run(url_list, dicts, gen_dict=False)
    for page in pages:
        item = page.dump_json()
        print(item)
