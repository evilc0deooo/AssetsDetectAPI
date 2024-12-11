# -*- coding: utf-8 -*-

import os
import thirdparty
from flask import make_response
from flask_restx import Namespace
from routes.__init__ import SimpleResource
from werkzeug.utils import secure_filename

ns = Namespace('image', description='截图信息')


def allowed_file(filename):
    """
    文件类型白名单
    """
    ALLOWED_EXTENSIONS = ['jpg', 'png']
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@ns.route('/<string:task_id>/<string:file_name>')
class Image(SimpleResource):
    """
    预览加载图片
    """

    @staticmethod
    def get(task_id, file_name):
        task_id = secure_filename(task_id)
        file_name = secure_filename(file_name)
        if not allowed_file(file_name):
            return
        img_path = os.path.join(thirdparty.SCREENSHOT_DIR, f'{task_id}/{file_name}')
        if os.path.exists(img_path):
            image_data = open(img_path, 'rb').read()
            response = make_response(image_data)
            response.headers['Content-Type'] = 'image/jpg'
            return response
        else:
            image_data = open(thirdparty.SCREENSHOT_FAIL_IMG, 'rb').read()
            response = make_response(image_data)
            response.headers['Content-Type'] = 'image/jpg'
            return response
