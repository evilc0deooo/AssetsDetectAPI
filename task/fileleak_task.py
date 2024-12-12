# -*- coding: utf-8 -*-

import time
import thirdparty
from bson import ObjectId
from common.mongo import conn_db
from task.common_task import CommonTask, WebSiteFetch
from common.log_msg import logger


class FileLeakTask(CommonTask):
    """
    敏感文件泄露任务流程
    """

    def __init__(self, url=None, task_id=None, options=None):
        super().__init__(task_id=task_id)
        self.url = url
        self.options = options

    def update_task_field(self, field=None, value=None):
        """
        更新任务状态字段
        """
        query = {'_id': ObjectId(self.task_id)}
        update = {'$set': {field: value}}
        conn_db('task').update_one(query, update)

    def update_services(self, services, elapsed):
        """
        实时显示当前阶段任务状态
        """
        elapsed = f'{elapsed:.2f}'
        self.update_task_field('status', services)
        query = {'_id': ObjectId(self.task_id)}
        update = {'$push': {'service': {'name': services, 'elapsed': float(elapsed)}}}
        conn_db('task').update_one(query, update)

    def task_statistic(self):
        """
        对任务中的资产信息进行统计
        """
        query = dict()
        task_id = self.task_id
        if isinstance(task_id, str) and len(task_id) == 24:
            query['task_id'] = task_id

        ret = dict()
        site_cnt = 'site_cnt'
        ret[site_cnt] = len(self.url)
        domain_cnt = 'domain_cnt'
        ret[domain_cnt] = 0
        return ret

    def insert_task_stat(self):
        """
        插入资产信息统计结果
        """
        query = {
            '_id': ObjectId(self.task_id)
        }
        stat = self.task_statistic()
        logger.info('insert task statistic')
        update = {'$set': {'statistic': stat}}
        conn_db('task').update_one(query, update)

    def start_site_fetch(self):
        self.update_task_field('status', 'file_leak')
        t1 = time.time()
        web_site_fetch = WebSiteFetch(task_id=self.task_id, sites=self.url, options=self.options)
        web_site_fetch.run()
        elapse = time.time() - t1
        self.update_services('file_leak', elapse)

    def run(self):
        """
        任务开始
        """
        self.update_task_field('start_time', thirdparty.curr_date(time.time()))
        self.start_site_fetch()
        self.insert_task_stat()

        # 任务结束
        self.update_task_field('status', 'done')
        self.update_task_field('end_time', thirdparty.curr_date(time.time()))


def file_scan_task(url, task_id, options):
    d = FileLeakTask(url=url, task_id=task_id, options=options)
    try:
        d.run()
    except Exception as e:
        logger.exception(e)
        d.update_task_field('status', 'error')
        d.update_task_field('end_time', thirdparty.curr_date(time.time()))
