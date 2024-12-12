# -*- coding: utf-8 -*-

import bson
import celerytask
from bson import ObjectId
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
    elif task_data['type'] == 'URL':
        conn_db('task').update_one({'_id': ObjectId(task_id)}, {'$set': {'target': 'file-leak'}})
        celery_action = 'file_leak_task'
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
