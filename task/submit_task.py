# -*- coding: utf-8 -*-

import bson
import celerytask
from common.mongo import conn_db


def submit_task(task_data):
    """
    提交任务
    """
    conn_db('task').insert_one(task_data)
    task_id = str(task_data.pop('_id'))
    task_data['task_id'] = task_id

    celery_action = 'domain_task'
    if task_data['type'] == 'DOMAIN':
        celery_action = 'domain_task'
    elif task_data['type'] == 'IP':
        celery_action = 'ip_exec_task'
    task_options = {
        'celery_action': celery_action,
        'data': task_data
    }

    # 异步执行任务, 不进行阻塞
    celery_id = celerytask.new_task.apply_async((task_options,))
    # 正常执行任务
    # celery_id = celerytask.new_task(task_options)
    task_data['celery_id'] = str(celery_id)
    values = {'$set': {'celery_id': str(celery_id)}}
    conn_db('task').update_one({'_id': bson.ObjectId(task_id)}, values)
    return task_data


def test_exec_task(task_data):
    """
    测试执行任务
    """
    submit_task(task_data)


if __name__ == '__main__':
    task_data = {
        'target': 'baidu.com',
        'start_time': '-',
        'status': 'waiting',
        'type': 'domain',
        'task_tag': 'task',
        'options': {'domain_brute': 'true',
                    'domain_brute_type': 'test',
                    'dns_query_plugin': False,
                    'alt_dns': False,
                    'skip_not_found_domain': False,
                    'port_scan': 'true',
                    'skip_scan_cdn_ip': 'true',
                    'port_scan_type': 'custom',
                    'port_custom': '80, 443, 22, 3335',
                    'service_detection': 'true',
                    'os_detection': False,
                    'ssl_cert': 'true',
                    'site_identify': 'true',
                    'site_capture': 'true',
                    'file_leak': 'true'},
        'end_time': '-',
        'service': [],
        'celery_id': '',
        'project_name': 'test project',
        'project_id': '1fd36b28-200a-43ed-983a-4e46d6f9e179'
    }

    test_exec_task(task_data)
