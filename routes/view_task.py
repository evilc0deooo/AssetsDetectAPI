# -*- coding: utf-8 -*-

import time
import thirdparty
from celery.result import AsyncResult
from flask_restx import fields, Namespace
from bson import ObjectId
from common.mongo import conn_db
from routes.__init__ import base_query_fields, SimpleResource, get_code_parser, build_ret
from routes.user import auth
import celerytask
from task.task_main import submit_task_task
from common.log_msg import logger

ns = Namespace('task', description='任务信息')

base_search_task_fields = {
    'project_id': fields.String(description='项目 ID'),
    'target': fields.String(description='任务目标'),
    'status': fields.String(description='任务状态'),
    '_id': fields.String(description='任务 ID'),
    'task_tag': fields.String(description='任务标签 -> 侦查任务和监控任务')
}

base_search_task_fields.update(base_query_fields)

search_task_fields = ns.model('SearchTask', base_search_task_fields)

add_task_fields = ns.model('AddTask', {
    'project_name': fields.String(required=True, description='项目名称'),
    'project_description': fields.String(required=True, description='项目描述'),
    'target': fields.String(required=True, description='目标'),
    'domain_brute': fields.Boolean(example=False, default=True),
    'domain_brute_type': fields.String(description='选择域名爆破字典'),
    'alt_dns': fields.Boolean(description='智能字典组合'),
    'dns_query_plugin': fields.Boolean(example=False, default=True, description='批量执行域名接口查询插件'),
    'skip_not_found_domain': fields.Boolean(description='域名搜集跳过泛解析只针对 dns_query_plugin 进行处理, 其他子域名搜集方法自带泛解析检测'),
    'port_scan': fields.Boolean(example=False, description='启动端口扫描'),
    'skip_scan_cdn_ip': fields.Boolean(example=False, description='端口扫描跳过 CDN'),
    'port_scan_type': fields.String(description='端口扫描类型'),
    'port_custom': fields.String(description='自定义端口扫描'),
    'service_detection': fields.Boolean(example=False, description='服务识别'),
    'os_detection': fields.Boolean(example=False, description='操作系统识别'),
    'ssl_cert': fields.Boolean(example=False, description='证书识别'),
    'site_identify': fields.Boolean(example=False, description='站点指纹'),
    'site_capture': fields.Boolean(example=False, description='站点截图'),
    'file_leak': fields.Boolean(example=False, description='目录爆破'),
    'only_file_leak': fields.Boolean(example=False, description='仅执行目录扫描'),
    'account': fields.String(example='admin', description='创建人'),
})


@ns.route('/')
class Task(SimpleResource):
    parser = get_code_parser(search_task_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        任务信息查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='task')
        return data

    @auth
    @ns.expect(add_task_fields)
    def post(self):
        """
        任务提交
        """
        args = self.parse_args(add_task_fields)
        project_name = args.pop('project_name')
        project_description = args.pop('project_description')
        account = args.pop('account')
        target = args.pop('target')

        try:
            task_data_list = submit_task_task(project_name=project_name, project_description=project_description, target=target, options=args, account=account)
        except Exception as e:
            logger.exception(e)
            return build_ret({'message': '系统异常', 'code': 300, }, {'error': str(e)})

        if not task_data_list:
            return build_ret({'message': '任务目标为空', 'code': 300, }, {'target': target})

        ret = {
            'code': 200,
            'message': 'success',
            'items': task_data_list
        }
        return ret


batch_stop_fields = ns.model('BatchStop', {
    'task_id': fields.List(fields.String(description='任务 ID'), required=True),
})


@ns.route('/batch_stop/')
class BatchStopTask(SimpleResource):

    @auth
    @ns.expect(batch_stop_fields)
    def post(self):
        """
        任务批量停止
        """
        args = self.parse_args(batch_stop_fields)
        task_id_list = args.pop('task_id', [])

        for task_id in task_id_list:
            if not task_id:
                continue
            stop_task(task_id)

        return build_ret({'message': 'success', 'code': 200}, {})


@ns.route('/stop/<string:task_id>')
class StopTask(SimpleResource):
    @auth
    def get(self, task_id=None):
        """
        任务停止
        """
        return stop_task(task_id=task_id)


def stop_task(task_id):
    """
    任务停止
    """
    done_status = ['done', 'stop', 'error']
    task_data = conn_db('task').find_one({'_id': ObjectId(task_id)})
    if not task_data:
        return build_ret({'message': '没有找到任务', 'code': 300}, {'task_id': task_id})

    if task_data['status'] in done_status:
        return build_ret({'message': '任务已经完成', 'code': 300}, {'task_id': task_id})

    celery_id = task_data.get('celery_id')
    if not celery_id:
        return build_ret({'message': '没有找到 Celery ID', 'code': 300}, {'task_id': task_id})

    result = AsyncResult(celery_id)
    control = celerytask.celery.control
    control.revoke(result.id, signal='SIGTERM', terminate=True)

    conn_db('task').update_one({'_id': ObjectId(task_id)}, {'$set': {'status': 'stop'}})
    conn_db('task').update_one({'_id': ObjectId(task_id)}, {'$set': {'end_time': thirdparty.curr_date(time.time())}})

    return build_ret({'message': 'success', 'code': 200}, {'task_id': task_id})


delete_task_fields = ns.model('DeleteTask', {
    'del_task_data': fields.Boolean(required=False, default=False, description='是否删除任务数据'),
    'task_id': fields.List(fields.String(required=True, description='任务 ID'))
})


@ns.route('/delete')
class DeleteTask(SimpleResource):
    @auth
    @ns.expect(delete_task_fields)
    def post(self):
        """
        任务删除
        """
        done_status = ['done', 'stop', 'error']
        args = self.parse_args(delete_task_fields)
        task_id_list = args.pop('task_id')
        del_task_data_flag = args.pop('del_task_data')
        for task_id in task_id_list:
            task_data = conn_db('task').find_one({'_id': ObjectId(task_id)})
            if not task_data:
                return build_ret({'message': '没有找到任务', 'code': 300}, {'task_id': task_id})

            if task_data['status'] not in done_status:
                return build_ret({'message': '任务正在运行', 'code': 300}, {'task_id': task_id})

        for task_id in task_id_list:
            conn_db('task').delete_many({'_id': ObjectId(task_id)})
            table_list = ['cert', 'domain', 'file_leak', 'ip', 'service', 'site', 'cip']
            if del_task_data_flag:
                for name in table_list:
                    conn_db(name).delete_many({'task_id': task_id})

        return build_ret({'message': 'success', 'code': 200}, {'task_id': task_id_list})
