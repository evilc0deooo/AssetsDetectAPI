# -*- coding: utf-8 -*-

from flask import Flask
from flask_restx import Api
from waitress import serve
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

api = Api(app, prefix='/api', doc='/api/docs', title='Assets Collection Platform API', authorizations=authorizations, description='Assets Collection Platform API', security='ApiKeyAuth', version='0.0.2')

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

if __name__ == '__main__':
    serve(app, host='127.0.0.1', port=5020, connection_limit=1000, channel_timeout=3600, threads=8)