# -*- coding: utf-8 -*-

from bson import ObjectId
from flask_restx import fields, Namespace
from routes.__init__ import base_query_fields, SimpleResource, get_code_parser, build_ret
from routes.user import auth
from common.mongo import conn_db

ns = Namespace('ip', description='IP 信息')

base_search_fields = {
    'ip': fields.String(required=False, description='IP'),
    'domain': fields.String(description='域名'),
    'port_info.port_id': fields.Integer(description='端口号'),
    'port_info.service_name': fields.String(description='系统服务名称'),
    'port_info.version': fields.String(description='系统服务版本'),
    'port_info.product': fields.String(description='产品'),
    'os_info.name': fields.String(description='操作系统名称'),
    'task_id': fields.String(description='任务 ID'),
    'ip_type': fields.String(description='IP 类型，公网(PUBLIC)和内网(PRIVATE)'),
    'cdn_name': fields.String(description='CDN 厂商名称'),
    'geo_asn.number': fields.Integer(description='AS number'),
    'geo_asn.organization': fields.String(description='AS organization')
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class AssetIP(SimpleResource):
    parser = get_code_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        IP 信息查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='ip')

        return data


delete_ip_fields = ns.model('deleteIpFields', {'_id': fields.List(fields.String(required=True, description='IP _id'))})


@ns.route('/delete')
class DeleteIP(SimpleResource):
    @auth
    @ns.expect(delete_ip_fields)
    def post(self):
        """
        删除 IP
        """
        args = self.parse_args(delete_ip_fields)
        id_list = args.pop('_id', [])
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            conn_db('ip').delete_one(query)

        return build_ret({'message': 'success', 'code': 200}, {'_id': id_list})
