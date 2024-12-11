# -*- coding: utf-8 -*-

from flask_restx import fields, Namespace
from routes.__init__ import base_query_fields, SimpleResource, get_code_parser
from routes.user import auth

ns = Namespace('cip', description='C 段 IP 统计信息')

base_search_fields = {
    'cidr_ip': fields.String(required=False, description='C 段'),
    'task_id': fields.String(description='任务 ID'),
    'ip_count': fields.Integer(description='IP 个数'),
    'domain_count': fields.Integer(description='解析到该 C 段域名个数')
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class CidrPrint(SimpleResource):
    parser = get_code_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        C 段统计信息查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='cip')

        return data
