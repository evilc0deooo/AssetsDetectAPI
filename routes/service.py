# -*- coding: utf-8 -*-

from flask_restx import fields, Namespace
from routes.__init__ import base_query_fields, SimpleResource, get_code_parser
from routes.user import auth

ns = Namespace('service', description='系统服务信息')

base_search_fields = {
    'service_name': fields.String(description='系统服务名称'),
    'service_info.ip': fields.String(required=False, description='IP'),
    'service_info.port_id': fields.Integer(description='端口号'),
    'service_info.version': fields.String(description='系统服务版本'),
    'service_info.product': fields.String(description='产品'),
    'task_id': fields.String(description='任务 ID')
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class Service(SimpleResource):
    parser = get_code_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        服务信息查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='service')

        return data
