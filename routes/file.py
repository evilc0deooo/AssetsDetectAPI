# -*- coding: utf-8 -*-

from bson import ObjectId
from flask_restx import fields, Namespace
from routes.__init__ import base_query_fields, SimpleResource, get_code_parser, build_ret
from routes.user import auth
from common.mongo import conn_db

ns = Namespace('file_leak', description='文件泄漏信息')

base_search_fields = {
    'url': fields.String(required=False, description='URL'),
    'site': fields.String(description='站点'),
    'content_length': fields.Integer(description='Body 长度'),
    'status_code': fields.Integer(description='状态码'),
    'title': fields.String(description='标题'),
    'task_id': fields.String(description='任务 ID')
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class FileLeak(SimpleResource):
    parser = get_code_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        文件泄露信息查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='file_leak')

        return data


delete_file_leak_fields = ns.model('deleteFileLeakFields', {
    '_id': fields.List(fields.String(required=True, description='文件泄漏 _id'))
})


@ns.route('/delete')
class DeleteFileLeak(SimpleResource):
    @auth
    @ns.expect(delete_file_leak_fields)
    def post(self):
        """
        删除 文件泄漏
        """
        args = self.parse_args(delete_file_leak_fields)
        id_list = args.pop('_id', [])
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            conn_db('file_leak').delete_one(query)

        return build_ret({'message': 'success', 'code': 200}, {'_id': id_list})
