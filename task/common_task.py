# -*- coding: utf-8 -*-

import time
import os
import thirdparty
from urllib.parse import urlparse
from bson import ObjectId
from common.mongo import conn_db
from utils.ip import IPInfo, is_vaild_ip_target
from services.web_analyze import run as web_analyze
from services.screenshot import run as site_screenshot
from services.screenshot import gen_filename
from services.fetch_site import run as fetch_site
from services.file_leak import run as file_leak
from services.check_http import run as check_http
from services.fetch_cert import run as fetch_cert
from config import FILE_LEAK_DICT
from common.log_msg import logger


# 任务类中一些相关公共类
class CommonTask(object):
    def __init__(self, task_id):
        self.task_id = task_id


class BaseUpdateTask(object):
    def __init__(self, task_id: str):
        self.task_id = task_id

    def update_services(self, service_name: str, elapsed: float):
        elapsed = f'{elapsed:.2f}'
        self.update_task_field('status', service_name)
        query = {'_id': ObjectId(self.task_id)}
        update = {'$push': {'service': {'name': service_name, 'elapsed': float(elapsed)}}}
        conn_db('task').update_one(query, update)

    def update_task_field(self, field=None, value=None):
        query = {'_id': ObjectId(self.task_id)}
        update = {'$set': {field: value}}
        conn_db('task').update_one(query, update)


class WebSiteFetch(object):
    def __init__(self, task_id: str, sites: list, options: dict):
        self.task_id = task_id
        self.sites = sites  # 这个是用户提交的目标
        self.options = options
        self.base_update_task = BaseUpdateTask(self.task_id)
        self.site_info_list = []  # 这个是来自 services.fetch_site 的结果
        self.available_sites = []  # 这个是存活的站点
        self.web_analyze_map = dict()  # 这是指纹识别的结果
        self._poc_sites = None  # 用于文件目录爆破的目标

    def site_identify(self):
        """
        调用指纹识别
        """
        self.web_analyze_map = web_analyze(self.available_sites)

    def __str__(self):
        return f'<WebSiteFetch> task_id:{self.task_id,}, sites: {len(self.sites)}, available_sites:{len(self.available_sites)}'

    def save_site_info(self):
        for site_info in self.site_info_list:
            curr_site = site_info['site']
            site_path = '/image/' + self.task_id
            file_name = f'{site_path}/{gen_filename(curr_site)}.jpg'
            site_info['task_id'] = self.task_id
            site_info['screenshot'] = file_name

            # 调用读取站点识别的结果，并且去重
            if self.web_analyze_map:
                finger_list = self.web_analyze_map.get(curr_site, [])
                known_finger_set = set()
                for finger_item in site_info['finger']:
                    known_finger_set.add(finger_item['name'].lower())

                for analyze_finger in finger_list:
                    analyze_name = analyze_finger['name'].lower()
                    if analyze_name not in known_finger_set:
                        site_info['finger'].append(analyze_finger)

        logger.info(f'save_site_info site:{len(self.site_info_list)}, {self.__str__()}')
        print(self.site_info_list)
        if self.site_info_list:
            conn_db('site').insert_many(self.site_info_list)

    def site_screenshot(self):
        """
        站点截图
        """
        capture_save_dir = thirdparty.SCREENSHOT_DIR + '/' + self.task_id
        site_screenshot(self.available_sites, concurrency=6, capture_dir=capture_save_dir)

    def fetch_site(self):
        """
        站点信息获取
        """
        self.site_info_list = fetch_site(self.sites)
        for site_info in self.site_info_list:
            curr_site = site_info['site']
            self.available_sites.append(curr_site)

    def file_leak(self):
        """
        目录爆破
        """
        for site in self.poc_sites:
            # 测试字典 -> FILE_LEAK_TEST_DICT
            # from config import FILE_LEAK_TEST_DICT
            # pages = file_leak([site], thirdparty.load_file(FILE_LEAK_TEST_DICT))
            pages = file_leak([site], thirdparty.load_file(FILE_LEAK_DICT))
            for page in pages:
                item = page.dump_json()
                item['task_id'] = self.task_id
                item['site'] = site
                conn_db('file_leak').insert_one(item)

    @staticmethod
    def cut_filename(url):
        """
        删除文件名称，规范 URL 方便目录爆破
        """
        o = urlparse(url)
        dir_path = os.path.dirname(o.path)
        dir_path = dir_path.rstrip('/')
        if not o.netloc:
            return ''
        ret_url = f'{o.scheme}://{o.netloc}{dir_path}'
        return ret_url

    @property
    def poc_sites(self):
        if self._poc_sites is None:
            self._poc_sites = set()
            for x in self.available_sites:
                cut_target = self.cut_filename(x)
                if cut_target:
                    self._poc_sites.add(cut_target)

        return self._poc_sites

    def run_func(self, name: str, func: callable):
        logger.info(f'start run {name}, {self.__str__()}')
        self.base_update_task.update_task_field('status', name)
        t1 = time.time()
        func()
        elapse = time.time() - t1
        self.base_update_task.update_services(name, elapse)

        logger.info(f'end run {name} ({elapse:.2f}s), {self.__str__()}')

    def run(self):
        """
        对站点进行基本信息的获取
        """
        if self.options.get('only_file_leak', False):
            self.available_sites = []
            self.available_sites = self.sites
            print(self.available_sites)
            """ 文件目录爆破 """
            self.file_leak()

        else:
            self.run_func('fetch_site', self.fetch_site)

            """ 执行站点指纹识别 """
            if self.options.get('site_identify', True):
                self.run_func('site_identify', self.site_identify)

            """ 保存站点信息到数据库 """
            self.save_site_info()

            """ 站点截图 """
            if self.options.get('site_capture', False):
                self.run_func('site_capture', self.site_screenshot)

            """ 文件目录爆破 """
            if self.options.get('file_leak', False):
                self.run_func('file_leak', self.file_leak)


class FindSite(object):
    def __init__(self, ip_info_list):
        self.ip_info_list = ip_info_list

    def _build(self):
        url_temp_list = []
        for info in self.ip_info_list:
            for domain in info.domain:
                for port_info in info.port_info_list:
                    port_id = port_info.port_id
                    if port_id == 80:
                        url_temp = f'http://{domain}'
                        url_temp_list.append(url_temp)
                        continue

                    if port_id == 443:
                        url_temp = f'https://{domain}'
                        url_temp_list.append(url_temp)
                        continue

                    url_temp1 = f'http://{domain}:{port_id}'
                    url_temp2 = f'https://{domain}:{port_id}'
                    url_temp_list.append(url_temp1)
                    url_temp_list.append(url_temp2)

        return url_temp_list

    def run(self):
        url_temp_list = set(self._build())
        start_time = time.time()
        check_map = check_http(url_temp_list)
        # 去除 https 和 http 相同的
        alive_site = []
        for x in check_map:
            if x.startswith('https://'):
                alive_site.append(x)

            elif x.startswith('http://'):
                x_temp = 'https://' + x[7:]
                if x_temp not in check_map:
                    alive_site.append(x)

        elapse = time.time() - start_time
        logger.info(f'end check_http result {len(alive_site)}, elapse {elapse}')

        return alive_site


class SSLCert(object):
    def __init__(self, ip_info_list, base_domain=None):
        self.ip_info_list = ip_info_list
        self.base_domain = base_domain

    def run(self):
        target_temp_list = []
        for info in self.ip_info_list:
            if isinstance(info, IPInfo):
                for port_info in info.port_info_list:
                    port_id = port_info.port_id
                    if port_id == 80:
                        continue

                    target_temp1 = f'{info.ip}:{port_id}'
                    target_temp_list.append(target_temp1)

            elif isinstance(info, str) and is_vaild_ip_target(info):
                target_temp_list.append(f'{info}:443')

            elif isinstance(info, str) and ':' in info:
                target_temp_list.append(info)

        cert_map = fetch_cert(target_temp_list)

        return cert_map


def find_site(ip_info_list):
    """
    在 IP 端口扫描结果内发现 Web 网站
    """
    f = FindSite(ip_info_list)
    return f.run()


def ssl_cert(ip_info_list, base_domain):
    """
    获取 SSL 证书
    """
    try:
        f = SSLCert(ip_info_list, base_domain)
        return f.run()
    except Exception as e:
        logger.exception(e)

    return {}


if __name__ == '__main__':
    task_id = '2017edf36591e76d16171b62'
    site_list = ['http://ng.zxebike.com', 'https://display.zxebike.com', 'https://enterprise.zxebike.com',
                 'https://localserver.zxebike.com', 'https://tm.zxebike.com', 'https://youyan.zxebike.com',
                 'https://www.baidu.com/', 'https://zxebike.com', 'https://www.zxebike.com',
                 'https://enterprise.zxebike.com/login/login', 'https://zhdj.nbpbl.com',
                 'https://zhdj.nbpbl.com/webroot/decision/login']

    options = {
        'only_file_leak': False,  # 只允许目录扫描
        'site_identify': True,  # 站点指纹识别
        'site_capture': True,  # 站点截图
        'file_leak': True,  # 目录扫描
    }
    web_site_fetch = WebSiteFetch(task_id=task_id, sites=site_list, options=options)
    web_site_fetch.run()
