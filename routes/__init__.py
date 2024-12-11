# -*- coding: utf-8 -*-

import re
from flask_restx import Resource, fields, reqparse
from bson.objectid import ObjectId
from datetime import datetime
from common.mongo import conn_db

# 定义返回给前端的数据格式
base_query_fields = {
    'page': fields.Integer(description='当前页数', example=1),
    'size': fields.Integer(description='页面大小', example=10),
    'order': fields.String(description='排序字段', example='_id'),
}

data_fields = {
    'result': fields.List(fields.Raw, description='查询结果'),
    'pagination': fields.Nested(base_query_fields, description='分页信息'),
}

# 只能用等号进行 mongo 查询的字段
EQUAL_FIELDS = ['task_id', 'task_tag', 'ip_type', 'scope_id', 'type']


class SimpleResource(Resource):
    @staticmethod
    def get_parser(model, location='json'):
        parser = reqparse.RequestParser(bundle_errors=True)
        for name in model:
            curr_field = model[name]
            parser.add_argument(name, required=curr_field.required, type=curr_field.format, help=curr_field.description, location=location)
        return parser

    def parse_args(self, model, location='json'):
        """
        解析请求中的参数
        """
        parser = self.get_parser(model, location)
        args = parser.parse_args()
        return args

    @staticmethod
    def get_default_field(args):
        """
        获取默认字段的值并从参数中删除这些字段
        """
        default_field_map = {
            'page': 1,
            'size': 10,
            'order': '-_id'
        }

        ret = default_field_map.copy()

        for x in default_field_map:
            if x in args and args[x]:
                ret[x] = args.pop(x)
                if x == 'size':
                    if ret[x] <= 0:
                        ret[x] = 10
                    if ret[x] >= 100000:
                        ret[x] = 100000

                if x == 'page':
                    if ret[x] <= 0:
                        ret[x] = 1

        orderby_list = []
        orderby_field = ret.get('order', '-_id')
        for field in orderby_field.split(','):
            field = field.strip()
            if field.startswith('-'):
                orderby_list.append((field.split('-')[1], -1))
            elif field.startswith('+'):
                orderby_list.append((field.split('+')[1], 1))
            else:
                orderby_list.append((field, 1))

        ret['order'] = orderby_list
        return ret

    @staticmethod
    def build_db_query(args):
        """
        构建 MongoDB 数据库查询参数
        """
        query_args = {}
        for key in args:
            if key in base_query_fields:
                continue

            if key == '_id':
                if args[key]:
                    query_args[key] = ObjectId(args[key])
                continue

            if args[key] is None:
                continue

            if key.endswith('__dgt'):
                real_key = key.split('__dgt')[0]
                raw_value = query_args.get(real_key, {})
                raw_value.update({'$gt': datetime.strptime(args[key], '%Y-%m-%d %H:%M:%S')})
                query_args[real_key] = raw_value

            elif key.endswith('__dlt'):
                real_key = key.split('__dlt')[0]
                raw_value = query_args.get(real_key, {})
                raw_value.update({'$lt': datetime.strptime(args[key], '%Y-%m-%d %H:%M:%S')})
                query_args[real_key] = raw_value

            elif isinstance(args[key], str):
                if key in EQUAL_FIELDS:  # 如果键在 EQUAL_FIELDS 中，直接使用相等条件
                    query_args[key] = args[key]
                else:
                    query_args[key] = {
                        '$regex': re.escape(args[key]),
                        '$options': 'i'
                    }
            else:
                query_args[key] = args[key]

        return query_args

    @staticmethod
    def build_return_items(data):
        items = []
        special_keys = ['_id', 'save_date', 'update_date']
        for item in data:
            for key in item:
                if key in special_keys:
                    item[key] = str(item[key])
            items.append(item)

        return items

    def build_data(self, args=None, collection=None):
        default_field = self.get_default_field(args)
        page = default_field.get('page', 1)
        size = default_field.get('size', 10)
        orderby_list = default_field.get('order', [('_id', -1)])
        query = self.build_db_query(args)
        result = conn_db(collection).find(query).sort(orderby_list).skip(size * (page - 1)).limit(size)
        count = conn_db(collection).count_documents(query)
        items = self.build_return_items(result)

        special_keys = ['_id', 'save_date', 'update_date']
        for key in query:
            if key in special_keys:
                query[key] = str(query[key])

        data = {
            'page': page,
            'size': size,
            'total': count,
            'items': items,
            'query': query,
            'code': 200
        }
        return data


def get_code_parser(model, location='args'):
    r = SimpleResource()
    return r.get_parser(model, location)


def build_ret(error, data):
    if isinstance(error, str):
        error = {'message': error, 'code': 999}

    ret = {}
    ret.update(error)
    ret['data'] = data
    msg = error['message']

    if error['code'] != 200:
        for k in data:
            if k.endswith('id'):
                continue
            if not data[k]:
                continue
            if isinstance(data[k], str):
                msg += f' -> ( {k}: {data[k]} )'

    ret['message'] = msg
    return ret

