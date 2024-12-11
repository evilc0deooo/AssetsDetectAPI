# -*- coding: utf-8 -*-

from flask import Flask
from flask_restx import Api
from routes import site, image, domain, ip, user, view_task, file, service, cert, project, cip

app = Flask(__name__)

app.config['BUNDLE_ERRORS'] = True

authorizations = {
    'ApiKeyAuth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Token'
    }
}

api = Api(app, prefix='/api', doc='/api/doc', title='API Platform', authorizations=authorizations,
          description='Nine Code Platform', security='ApiKeyAuth', version='0.0.1')

api.add_namespace(user.ns)
api.add_namespace(project.ns)
api.add_namespace(view_task.ns)
api.add_namespace(domain.ns)
api.add_namespace(ip.ns)
api.add_namespace(site.ns)
api.add_namespace(image.ns)
api.add_namespace(file.ns)
api.add_namespace(service.ns)
api.add_namespace(cert.ns)
api.add_namespace(cip.ns)

# 初始化账号密码 admin / !@#password
# user.init_user()

if __name__ == '__main__':
    app.run(debug=True, port=5020, host='0.0.0.0')
