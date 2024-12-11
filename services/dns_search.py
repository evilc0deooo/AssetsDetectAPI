# -*- coding: utf-8 -*-

import os
import time
import importlib.util
from utils.domain import check_domain_black
from config import DNS_SEARCH_PLUG_PATH, DOMAIN_MAX_LEN
from common.log_msg import logger


def import_source(spec, path):
    module_spec = importlib.util.spec_from_file_location(spec, path)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


def walk_py(path):
    for dir_path, dir_names, filenames in os.walk(path):
        if dir_path.endswith('__pycache__'):
            continue
        for f in filenames:
            if f.startswith('_'):
                continue
            split = f.split('.')
            if len(split) == 2 and split[1] == 'py':
                abspath = os.path.abspath(os.path.join(dir_path, f))
                yield abspath, split[0]


def load_query_plugins(path):
    """
    加载 DNS 域名查询插件
    """
    plugins = []
    for file_path, name in walk_py(path):
        try:
            plugin_module = import_source(spec='query_plugins', path=file_path)
            plugin = getattr(plugin_module, 'run')
            plugins.append(plugin)
        except Exception as e:
            logger.warning(f'load query plugin error from {file_path}')
            logger.exception(e)

    return plugins


def run_query_plugin(target):
    """
    批量执行接口子域名查询插件
    """
    plugins = load_query_plugins(DNS_SEARCH_PLUG_PATH)
    domains = []
    temporary_domain = []
    t1 = time.time()
    for p in plugins:
        results = p(target)
        if not results:
            continue
        source_name = results.get('source_name')
        _subdomains = results.get('subdomains')
        subdomains = []

        # 过滤掉不合法的域名数据
        for domain in _subdomains:
            domain = domain.strip('*.')
            domain = domain.lower()
            if not domain:
                continue

            # 删除掉过长的子域名
            if len(domain) - len(target) >= DOMAIN_MAX_LEN:
                continue

            # 屏蔽和谐域名和黑名单子域名
            if check_domain_black(domain):
                continue

            # 子域名集去重
            if domain in temporary_domain:
                continue

            subdomains.append(domain)
            temporary_domain.append(domain)

        subdomains = list(set(subdomains))

        item = {
            'subdomains': subdomains,
            'source': source_name
        }

        domains.append(item)

    if not isinstance(domains, list):
        logger.warning(f'{domains} is not list')
        return []

    # 计算所有子域名数量
    total_count = sum(len(d['subdomains']) for d in domains)
    t2 = time.time()
    logger.info(f'{target} subdomains result {total_count} ({t2 - t1:.2f}s)')

    return domains
