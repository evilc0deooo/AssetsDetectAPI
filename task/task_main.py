# -*- coding: utf-8 -*-

import re
import time
import uuid
import thirdparty
from common.mongo import conn_db
from task.submit_task import submit_task
from utils.ip import is_vaild_ip_target, not_in_black_ips
from utils.domain import is_forbidden_domain, is_valid_domain, is_valid_fuzz_domain


def target2list(target):
    target = target.strip().lower()
    target_lists = re.split(r',|\s', target)
    # 清除空白符
    target_lists = list(filter(None, target_lists))
    target_lists = list(set(target_lists))

    return target_lists


def get_ip_domain_url_list(target):
    """
    获取 IP 、域名列表、url 列表
    """
    target_lists = target2list(target)
    ip_list = set()
    domain_list = set()
    url_list = set()
    for item in target_lists:
        if not item:
            continue

        # 如果带有 http 字符判断为 url
        if 'http' in item:
            url_list.add(item)

        elif is_vaild_ip_target(item):
            if not not_in_black_ips(item):
                raise Exception(f'{item} 在黑名单 IP 中')
            ip_list.add(item)

        elif is_forbidden_domain(item):
            raise Exception(f'{item} 包含在禁止域名内')

        elif is_valid_domain(item):
            domain_list.add(item)

        elif is_valid_fuzz_domain(item):
            domain_list.add(item)
        else:
            raise Exception(f'{item} 无效的目标')

    return ip_list, domain_list, url_list


def build_task_data(project_id, project_name, task_target, task_type, task_tag, options):
    # 检查是不是正常的任务目标类别

    avail_task_type = ['IP', 'DOMAIN', 'URL', 'RISK_CRUISING']
    if task_type not in avail_task_type:
        raise Exception(f'{task_type} 无效的任务类型')

    # 检查是正常任务还是风险巡航任务
    avail_task_tag = ['task', 'risk_cruising']
    if task_tag not in avail_task_tag:
        raise Exception(f'{task_type} 无效的任务标签')

    if not isinstance(options, dict):
        raise Exception(f'{options} 不是 dict 类型')

    options_cp = options.copy()

    # 针对 IP 任务关闭下面的选项
    if task_type == 'IP':
        disable_options = {
            'domain_brute': False,
            'alt_dns': False,
            'dns_query_plugin': False
        }
        options_cp.update(disable_options)

    task_data = {
        'target': task_target,
        'start_time': '-',
        'status': 'waiting',
        'type': task_type,
        'task_tag': task_tag,
        'options': options_cp,
        'end_time': '-',
        'service': [],
        'celery_id': '',
        'project_name': project_name,
        'project_id': project_id
    }

    if task_tag == 'risk_cruising':
        pass  # 单独对风险巡航任务处理该功能暂且没有需求

    return task_data


def submit_task_task(project_name, target, options, project_description, account='admin'):
    """
    直接根据目标下发任务
    """

    # 创建项目

    if not project_description or project_description == 'null':
        project_description = 'Good Job :)'

    project_info = {
        'project_name': project_name,
        'project_description': project_description,
        'account': account,
        'create_time': thirdparty.curr_date(time.time()),
    }
    project_id = str(uuid.uuid4())
    project_info['project_id'] = project_id
    conn_db('project').insert_one(project_info)

    task_data_list = []

    ip_list, domain_list, url_list = get_ip_domain_url_list(target)
    if ip_list:
        # 针对 IP 扫描任务
        for ip in ip_list:
            task_data = build_task_data(project_id=project_id, project_name=project_name, task_target=ip, task_type='IP', task_tag='task', options=options)
            task_data = submit_task(task_data)
            task_data_list.append(task_data)

    if domain_list:
        # 针对域名扫描任务
        for domain_target in domain_list:
            task_data = build_task_data(project_id=project_id, project_name=project_name, task_target=domain_target, task_type='DOMAIN', task_tag='task', options=options)
            task_data = submit_task(task_data)
            task_data_list.append(task_data)

    if url_list:
        # 针对 URL 直接目录扫描任务
        task_data = build_task_data(project_id=project_id, project_name=project_name, task_target=list(url_list), task_type='URL', task_tag='task', options=options)
        task_data = submit_task(task_data)
        task_data_list.append(task_data)

    return task_data_list


if __name__ == '__main__':
    """
    测试任务入口
    """
    options = {
        'domain_brute': 'true',  # 域名爆破
        'domain_brute_type': 'test',  # 域名爆破字典
        'dns_query_plugin': False,  # 批量执行域名接口查询插件
        'alt_dns': 'true',  # 智能域名生成
        'skip_not_found_domain': False,  # 域名搜集跳过泛解析，只针对 dns_query_plugin 进行处理，其他子域名搜集方法自带泛解析检测
        'port_scan': 'true',  # 启动端口扫描
        'skip_scan_cdn_ip': 'true',  # 端口扫描跳过 CDN
        'port_scan_type': 'custom',  # 扫描字典类型
        'port_custom': '80, 443, 22',  # 自定义端口扫描
        'service_detection': 'true',  # 服务识别
        'os_detection': False,  # 操作系统识别
        'ssl_cert': 'true',  # 证书识别
        'site_identify': 'true',  # 站点指纹
        'site_capture': 'true',  # 站点截图
        'only_file_leak': 'true',  # 仅执行目录扫描
        'file_leak': 'true',  # 目录爆破
    }
    submit_task_task(project_name='test project2',
                     project_description='test project2',
                     target='''
                        http://ng.zxebike.com
                        https://display.zxebike.com
                        https://enterprise.zxebike.com
                        https://localserver.zxebike.com
                        https://tm.zxebike.com
                        https://youyan.zxebike.com
                        https://www.baidu.com/
                        https://www.baidu.com/
                        https://www.baidu.com/
                        https://zxebike.com
                        https://www.zxebike.com
                        https://enterprise.zxebike.com/login/login
                        https://zhdj.nbpbl.com
                        https://zhdj.nbpbl.com/webroot/decision/login
                     ''',
                     options=options)
