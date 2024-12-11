# -*- coding: utf-8 -*-

import time
from common.conn import http_req
from common.base_thread import BaseThread
import requests.exceptions
from common.log_msg import logger


class CheckHTTP(BaseThread):
    def __init__(self, urls, concurrency=10):
        super().__init__(urls, concurrency=concurrency)
        self.timeout = (5, 3)
        self.checkout_map = {}

    def check(self, url):
        conn = http_req(url, method='head', timeout=self.timeout)
        if conn.status_code == 400:
            # 特殊情况排除
            etag = conn.headers.get('ETag')
            date = conn.headers.get('Date')
            if not etag or not date:
                return None

        # 特殊情况过滤
        if conn.status_code == 422 or conn.status_code == 410:
            return None

        if (conn.status_code >= 501) and (conn.status_code < 600):
            return None

        if conn.status_code == 403:
            conn2 = http_req(url)
            check = b'</title><style type="text/css">body{margin:5% auto 0 auto;padding:0 18px}'
            if check in conn2.content:
                return None

        item = {
            'status': conn.status_code,
            'content-type': conn.headers.get('Content-Type', '')
        }

        return item

    def work(self, url):
        try:
            out = self.check(url)
            if out is not None:
                self.checkout_map[url] = out

        except requests.exceptions.RequestException:
            pass

        except Exception as e:
            logger.warning(f'error on url {url}')
            logger.warning(e)

    def run(self):
        t1 = time.time()
        logger.info(f'start check http {len(self.targets)}')
        self._run()
        elapse = time.time() - t1
        logger.info(f'end check http elapse {elapse}')
        return self.checkout_map


def run(urls, concurrency=15):
    c = CheckHTTP(urls, concurrency)
    return c.run()
