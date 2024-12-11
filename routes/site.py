# -*- coding: utf-8 -*-

import copy
from bson import ObjectId
from flask_restx import fields, Namespace
from routes.__init__ import base_query_fields, SimpleResource, get_code_parser, build_ret
from routes.user import auth
from common.mongo import conn_db

ns = Namespace('site', description='站点信息')

base_search_fields = {
    'site': fields.String(required=False, description='站点 URL'),
    'hostname': fields.String(description='主机名'),
    'ip': fields.String(description='IP'),
    'title': fields.String(description='标题'),
    'http_server': fields.String(description='Web Servers'),
    'headers': fields.String(description='Headers'),
    'finger.name': fields.String(description='指纹'),
    'status': fields.Integer(description='状态码'),
    'favicon.hash': fields.Integer(description='Favicon Hash'),
    'task_id': fields.String(description='任务 ID'),
    'tag': fields.String(description='标签列表')
}

site_search_fields = copy.copy(base_search_fields)

base_search_fields.update(base_query_fields)


@ns.route('/')
class AssetSite(SimpleResource):
    parser = get_code_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        站点信息查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='site')

        return data


add_site_tag_fields = ns.model('AddSiteTagFields', {
    'tag': fields.String(required=True, description='添加站点标签'),
    '_id': fields.String(description='站点 ID', required=True)
})


@ns.route('/add_tag')
class AddSiteTag(SimpleResource):
    @auth
    @ns.expect(add_site_tag_fields)
    def post(self):
        """
        站点添加 Tag
        """
        args = self.parse_args(add_site_tag_fields)
        site_id = args.pop('_id')
        tag = args.pop('tag')
        query = {'_id': ObjectId(site_id)}
        data = conn_db('site').find_one(query)
        if not data:
            return build_ret({'message': 'site not found', 'code': 300}, {'site_id': site_id})

        tag_list = []
        old_tag = data.get('tag')
        if old_tag:
            if isinstance(old_tag, str):
                tag_list.append(old_tag)
            if isinstance(old_tag, list):
                tag_list.extend(old_tag)

        if tag in tag_list:
            return build_ret({'message': 'site tag is exist', 'code': 300}, {'tag': tag})

        tag_list.append(tag)
        conn_db('site').update_one(query, {'$set': {'tag': tag_list}})
        return build_ret({'message': 'success', 'code': 200}, {'tag': tag})


delete_site_tag_fields = ns.model('DeleteSiteTagFields', {
    'tag': fields.String(required=True, description='删除站点标签'),
    '_id': fields.String(description='站点 ID', required=True)
})


@ns.route('/delete_tag')
class DeleteSiteTag(SimpleResource):
    @auth
    @ns.expect(delete_site_tag_fields)
    def post(self):
        """
        删除站点 Tag
        """
        args = self.parse_args(delete_site_tag_fields)
        site_id = args.pop('_id')
        tag = args.pop('tag')
        query = {'_id': ObjectId(site_id)}
        data = conn_db('site').find_one(query)
        if not data:
            return build_ret({'message': 'site tag is exist', 'code': 300}, {'site_id': site_id})

        tag_list = []
        old_tag = data.get('tag')
        if old_tag:
            if isinstance(old_tag, str):
                tag_list.append(old_tag)

            if isinstance(old_tag, list):
                tag_list.extend(old_tag)

        if tag not in tag_list:
            return build_ret({'message': 'site tag not found', 'code': 300}, {'tag': tag})

        tag_list.remove(tag)
        conn_db('site').update_one(query, {'$set': {'tag': tag_list}})
        return build_ret({'message': 'success', 'code': 200}, {'tag': tag})


delete_site_fields = ns.model('deleteSiteFields', {
    '_id': fields.List(fields.String(required=True, description='站点 _id'))
})


@ns.route('/delete')
class DeleteSite(SimpleResource):
    @auth
    @ns.expect(delete_site_fields)
    def post(self):
        """
        删除站点
        """
        args = self.parse_args(delete_site_fields)
        id_list = args.pop('_id', [])
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            conn_db('site').delete_one(query)

        return build_ret({'message': 'success', 'code': 200}, {'_id': id_list})
