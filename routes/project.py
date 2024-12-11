# -*- coding: utf-8 -*-

from flask_restx import fields, Namespace
from routes.__init__ import base_query_fields, SimpleResource, get_code_parser, build_ret
from routes.user import auth
from common.mongo import conn_db

ns = Namespace('project', description='项目信息')

base_search_project_fields = {
    'project_id': fields.String(description='项目 ID'),
    'project_name': fields.String(description='项目名称'),
    'project_description': fields.String(description='项目描述')
}

base_search_project_fields.update(base_query_fields)

search_project_fields = ns.model('SearchProject', base_search_project_fields)


@ns.route('/')
class Project(SimpleResource):
    parser = get_code_parser(search_project_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        项目信息查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='project')

        return data


delete_project_fields = ns.model('DeleteProject', {
    'del_task_data': fields.Boolean(required=False, default=False, description='是否删除任务数据'),
    'project_id': fields.List(fields.String(required=True, description='项目 ID'))
})


@ns.route('/delete')
class DeleteTask(SimpleResource):
    @auth
    @ns.expect(delete_project_fields)
    def post(self):
        """
        项目删除
        """
        args = self.parse_args(delete_project_fields)
        project_id_list = args.pop('project_id')
        del_task_data_flag = args.pop('del_task_data')
        for project_id in project_id_list:
            project_data = conn_db('project').find_one({'project_id': project_id})
            if not project_data:
                return build_ret({'message': '没有找到项目', 'code': 300}, {'project_id': project_id})

            conn_db('project').delete_many({'project_id': project_id})
            task_data = conn_db('task').find({'project_id': project_id})
            task_id_list = [str(doc['_id']) for doc in task_data]
            if not task_id_list:
                return build_ret({'message': '没有找到任务 ID', 'code': 300}, {'project_id': project_id})

            conn_db('task').delete_many({'project_id': project_id})
            table_list = ['cert', 'domain', 'file_leak', 'ip', 'service', 'site', 'cip']
            if del_task_data_flag:
                for task_id in task_id_list:
                    for name in table_list:
                        conn_db(name).delete_many({'task_id': task_id})

        return build_ret({'message': 'success', 'code': 200}, {'project_id': project_id_list})
