# -*- coding: utf-8 -*-

import functools
from flask import request
from flask_restx import fields, Namespace
from routes.__init__ import SimpleResource
from common.mongo import conn_db
from thirdparty import random_choices, gen_md5
from config import AUTH, API_KEY

salt = '!@#saltjwt_'


def init_user():
    """
    初始化用户
    """
    password = '!@#password'
    conn_db('user').insert_one({'username': 'admin', 'password': gen_md5(salt + password)})


def build_data(data):
    ret = {
        'message': 'success',
        'code': 200,
        'data': {}
    }

    if data:
        ret['data'] = data
    else:
        ret['code'] = 401

    return ret


def user_login(username=None, password=None):
    if not username or not password:
        return

    query = {'username': username, 'password': gen_md5(salt + password)}

    if conn_db('user').find_one(query):
        item = {
            'username': username,
            'token': gen_md5(random_choices(50)),
            'type': 'login'
        }
        conn_db('user').update_one(query, {'$set': {'token': item['token']}})

        return item


def user_login_header():
    token = request.headers.get('Token') or request.args.get('token')
    if not AUTH:
        return True

    item = {
        'username': 'api_user',
        'token': API_KEY,
        'type': 'api'
    }

    if not token:
        return False

    if token == API_KEY:
        return item

    data = conn_db('user').find_one({'token': token})
    if data:
        item['username'] = data.get('username')
        item['token'] = token
        item['type'] = 'login'
        return item

    return False


def user_logout(token):
    """
    登出并销毁 token
    """
    if user_login_header():
        conn_db('user').update_one({'token': token}, {'$set': {'token': None}})


def change_pass(token, old_password, new_password):
    """
    修改密码
    """
    query = {'token': token, 'password': gen_md5(salt + old_password)}
    data = conn_db('user').find_one(query)
    if data:
        conn_db('user').update_one({'token': token}, {'$set': {'password': gen_md5(salt + new_password)}})
        return True
    else:
        return False


def auth(func):
    ret = {
        'message': 'not login',
        'code': 300,
        'data': {}
    }

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if AUTH and not user_login_header():
            return ret

        return func(*args, **kwargs)

    return wrapper


ns = Namespace('user', description='登录认证')

login_fields = ns.model('Login', {
    'username': fields.String(required=True, description='用户名'),
    'password': fields.String(required=True, description='密码'),
})


@ns.route('/login')
class Login(SimpleResource):

    @ns.expect(login_fields)
    def post(self):
        """
        用户登录
        """
        args = self.parse_args(login_fields)
        return build_data(user_login(**args))


@ns.route('/logout')
class Logout(SimpleResource):
    @staticmethod
    def get():
        """
        用户退出
        """
        token = request.headers.get('Token')
        user_logout(token)

        return build_data({})


change_pass_fields = ns.model('ChangePassword', {
    'old_password': fields.String(required=True, description='旧密码'),
    'new_password': fields.String(required=True, description='新密码'),
    'check_password': fields.String(required=True, description='确认密码'),
})


@ns.route('/change_pass')
class ChangePass(SimpleResource):
    @auth
    @ns.expect(change_pass_fields)
    def post(self):
        """
        密码修改
        """
        args = self.parse_args(change_pass_fields)
        ret = {
            'message': 'success',
            'code': 200,
            'data': {}
        }
        token = request.headers.get('Token')

        if args['new_password'] != args['check_password']:
            ret['code'] = 301
            ret['message'] = '新密码和确定密码不一致'
            return ret

        if not args['new_password']:
            ret['code'] = 302
            ret['message'] = '新密码不能为空'
            return ret

        if change_pass(token, args['old_password'], args['new_password']):
            user_logout(token)
        else:
            ret['message'] = '旧密码错误'
            ret['code'] = 303

        return ret
