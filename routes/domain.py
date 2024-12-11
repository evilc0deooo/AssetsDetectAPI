# -*- coding: utf-8 -*-

from bson import ObjectId
from flask_restx import fields, Namespace
from routes.__init__ import base_query_fields, SimpleResource, get_code_parser, build_ret
from routes.user import auth
from common.mongo import conn_db

ns = Namespace('domain', description='域名信息')

base_search_fields = {
    'domain': fields.String(required=False, description='域名'),
    'record': fields.String(description='解析值'),
    'type': fields.String(description='解析类型'),
    'ips': fields.String(description='IP'),
    'source': fields.String(description='来源'),
    'task_id': fields.String(description='任务 ID')
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class AssetDomain(SimpleResource):
    parser = get_code_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        域名信息查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='domain')

        return data


delete_domain_fields = ns.model('deleteDomainFields', {'_id': fields.List(fields.String(required=True, description='域名 _id'))})


@ns.route('/delete')
class DeleteDomain(SimpleResource):
    @auth
    @ns.expect(delete_domain_fields)
    def post(self):
        """
        删除域名
        """
        args = self.parse_args(delete_domain_fields)
        id_list = args.pop('_id', [])
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            conn_db('domain').delete_one(query)

        return build_ret({'message': 'success', 'code': 200}, {'_id': id_list})
