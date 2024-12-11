# -*- coding: utf-8 -*-

from bson import ObjectId
from flask_restx import fields, Namespace
from routes.__init__ import base_query_fields, SimpleResource, get_code_parser, build_ret
from routes.user import auth
from common.mongo import conn_db

ns = Namespace('cert', description='证书信息')

base_search_fields = {
    'ip': fields.String(description='IP'),
    'port': fields.Integer(description='端口'),
    'cert.subject_dn': fields.String(description='主题名称'),
    'cert.issuer_dn': fields.String(description='签发者名称'),
    'cert.serial_number ': fields.String(description='序列号'),
    'cert.validity.start': fields.String(description='开始时间'),
    'cert.validity.end': fields.String(description='结束时间'),
    'cert.fingerprint.sha256': fields.String(description='SHA-256'),
    'cert.fingerprint.sha1': fields.String(description='SHA-1'),
    'cert.fingerprint.md5': fields.String(description='MD5'),
    'cert.extensions.subjectAltName': fields.String(description='备用名称'),
    'task_id': fields.String(description='任务 ID'),
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class Cert(SimpleResource):
    parser = get_code_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        SSL 证书查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='cert')

        return data


delete_cert_fields = ns.model('deleteCertFields', {
    '_id': fields.List(fields.String(required=True, description='证书 _id'))
})


@ns.route('/delete/')
class DeleteCert(SimpleResource):
    @auth
    @ns.expect(delete_cert_fields)
    def post(self):
        """
        删除 SSL 证书信息
        """
        args = self.parse_args(delete_cert_fields)
        id_list = args.pop('_id', [])
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            conn_db('cert').delete_one(query)

        return build_ret({'message': 'success', 'code': 200}, {'_id': id_list})
