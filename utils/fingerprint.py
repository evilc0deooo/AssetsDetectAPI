# -*- coding: utf-8 -*-

import json
import thirdparty
from config import WEB_APP_PATH
from config import WEB_FINGER_PATH
from common.log_msg import logger

# 解析规则，只有或，且条件不能出现 =

'''
html
title
headers
favicon_hash
'''


def parse_human_rule(rule):
    """
    解析规则
    """
    rule_map = {
        'html': [],
        'title': [],
        'headers': [],
        'favicon_hash': []
    }
    key_map = {
        'body': 'html',
        'title': 'title',
        'header': 'headers',
        'icon_hash': 'favicon_hash'
    }
    split_result = rule.split('||')
    empty_flag = True

    for item in split_result:
        key_value = item.split('=')
        key = key_value[0]
        key = key.strip()
        if len(key_value) == 2:
            if key not in key_map:
                logger.info(f'{key} 不在指定关键字中')
                continue

            value = key_value[1]
            value = value.strip()
            if len(value) <= 6:
                logger.info(f'{value} 长度少于 7')
                continue

            if value[0] != '"' or value[-1] != '"':
                logger.info(f'{value} 没有在双引号内')
                continue

            empty_flag = False

            # 防御性转换成gbk
            value.encode('gbk')

            value = value[1:-1]
            if key == 'icon_hash':
                value = int(value)

            rule_map[key_map[key]].append(value)

    if empty_flag:
        return None

    return rule_map


def transform_rule_map(rule):
    key_map = {
        'html': 'body',
        'title': 'title',
        'headers': 'header',
        'favicon_hash': 'icon_hash'
    }
    human_rule_list = []
    for key in rule:
        if key not in key_map:
            logger.info(f'{key} 不在指定关键字中')
            continue

        for rule_item in rule[key]:
            human_rule_list.append(f'{key_map[key]}="{rule_item}"')

    return ' || '.join(human_rule_list)


web_app_rules = json.loads('\n'.join(thirdparty.load_file(WEB_APP_PATH)))

# EHole Web 指纹库
web_finger_rules = json.loads('\n'.join(thirdparty.load_file(WEB_FINGER_PATH)))


def load_fingerprint():
    """
    加载指纹规则库
    """
    items = web_finger_rules
    # items = []
    for rule in web_app_rules:
        new_rule = dict()
        new_rule['name'] = rule
        new_rule['rule'] = web_app_rules[rule]
        items.append(new_rule)

    return items


def fetch_fingerprint(content, headers, title, favicon_hash, finger_list):
    finger_name_list = []

    # 根据规则列表来获取应用名，单个规则字段是或的关系
    for finger in finger_list:
        rule = finger['rule']
        rule_name = finger['name']
        match_flag = False
        for html in rule['html']:
            if html.encode('utf-8') in content:
                finger_name_list.append(rule_name)
                match_flag = True
                break

            try:
                if html.encode('gbk') in content:
                    finger_name_list.append(rule_name)
                    match_flag = True
                    break
            except Exception:
                logger.debug(f'error on fetch_fingerprint {html} to gbk')

        if match_flag:
            continue

        for header in rule['headers']:
            if header in headers:
                finger_name_list.append(rule_name)
                match_flag = True
                break

        if match_flag:
            continue

        for rule_title in rule['title']:
            if rule_title in title:
                finger_name_list.append(rule_name)
                match_flag = True
                break

        if match_flag:
            continue

        if isinstance(rule.get('favicon_hash'), list):
            for rule_hash in rule['favicon_hash']:
                if rule_hash == favicon_hash:
                    finger_name_list.append(rule_name)
                    break

    return finger_name_list


# 一次性加载指纹库，防止多次加载
FINGERPRINT = load_fingerprint()

if __name__ == '__main__':
    load_fingerprint()
