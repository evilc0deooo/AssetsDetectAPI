# -*- coding: utf-8 -*-

import time
import signal
import os
import psutil
import logging
from bson import ObjectId
from common.log_msg import result_save_dir
from common.mongo import conn_db
from celery import Celery, platforms
from logging.handlers import RotatingFileHandler
from task.domain_task import domain_task as DomainTask
from task.ip_task import ip_task as IP_Task
from task.fileleak_task import file_scan_task as fileLeak_Task
from config import CELERY_BROKER_URL, RESULT_BACKEND_URL
from common.log_msg import logger

celery_log_path = result_save_dir.joinpath('celery.log')  # 日志保存路径

# 限制 celery 日志文件过大，导致系统内存不够的问题
handler = RotatingFileHandler(celery_log_path, maxBytes=5 * 1024 * 1024, backupCount=5)  # 5MB, 保留 5 个备份
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
celery_logger = logging.getLogger('celery')
celery_logger.addHandler(handler)
celery_logger.setLevel(logging.DEBUG)

celery = Celery('task', broker=CELERY_BROKER_URL, result_backend=RESULT_BACKEND_URL)

celery.conf.update(
    task_acks_late=False,
    worker_prefetch_multiplier=1,
    broker_transport_options={'max_retries': 3, 'interval_start': 0, 'interval_step': 0.2, 'interval_max': 0.5},
    broker_connection_retry_on_startup=True,
)
platforms.C_FORCE_ROOT = True

"""
python3 -m celery -A celerytask.celery worker -l debug -Q assets_task -n celery_task -c 2 -O fair -f logs/celery.log
"""


@celery.task(queue='assets_task')
def new_task(options):
    run_task(options)


def exit_gracefully(signum, frame):
    logger.info(f'receive signal {signum} frame {frame}')
    pid = os.getpid()
    kill_child_process(pid)
    parent = psutil.Process(pid)
    logger.info(f'kill self {parent}')
    parent.kill()


def kill_child_process(pid):
    parent = psutil.Process(pid)
    for child in parent.children(recursive=True):
        logger.info(f'kill child_process {child}')
        child.kill()


def domain_task(options):
    """
    常规域名任务
    """
    target = options['target']
    task_options = options['options']
    task_id = options['task_id']
    item = conn_db('task').find_one({'_id': ObjectId(task_id)})
    if not item:
        logger.info(f'domain_task not found {target} {item}')
        return
    DomainTask(target, task_id, task_options)


def ip_task(options):
    """
    常规 IP 任务
    """
    target = options['target']
    task_options = options['options']
    task_id = options['task_id']
    IP_Task(target, task_id, task_options)

def file_leak_task(options):
    """
    常规目录扫描任务（单独执行）
    """
    url = options['target']
    task_options = options['options']
    task_id = options['task_id']
    fileLeak_Task(url, task_id, task_options)


def run_task(options):
    """
    开始任务
    """
    signal.signal(signal.SIGTERM, exit_gracefully)
    action = options.get('celery_action')
    data = options.get('data')
    action_map = {
        'domain_task': domain_task,
        'ip_exec_task': ip_task,
        'file_leak_task': file_leak_task,
    }
    start_time = time.time()
    logger.info(f'run_task action: {action} time: {start_time}')
    project_name = data.get('project_name')
    target = data.get('target')
    task_id = data.get('task_id')
    logger.info(f'project_name:{project_name}, target: {target}, task_id:{task_id}')
    try:
        fun = action_map.get(action)
        if fun:
            fun(data)
        else:
            logger.warning(f'not found {action} action')
    except Exception as e:
        logger.exception(e)

    elapsed = time.time() - start_time
    logger.info(f'end {action} elapsed: {elapsed}')
