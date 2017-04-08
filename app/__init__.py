#!/usr/bin/env python
# -*- coding: utf-8 -*-
import flask
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restplus import Api
from flask_jwt import JWT, JWTError
from flask_cors import CORS
from werkzeug.contrib.profiler import ProfilerMiddleware
from werkzeug.exceptions import HTTPException

app = Flask(__name__, instance_relative_config=True,
            template_folder='../templates')


# Load the default configuration
app.config.from_object('config.default')

# Load the configuration from the instance folder
try:
    app.config.from_pyfile('config.py')
except IOError:
    pass

# Load the file specified by the LWP_CONFIG_FILE environment variable
# Variables defined here will override those in the default configuration
try:
    app.config.from_envvar('LWP_CONFIG_FILE')
except RuntimeError:
    pass

try:
    if app.config['PROFILE']:
        app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[30])
except KeyError:
    pass


def authenticate(username, password):
    user = User.query.filter_by(username=username).first()

    if not user or not user.verify_password(password):
        return False

    return user


class ExceptionAwareApi(Api):

    def handle_error(self, e):
        if isinstance(e, JWTError):
            code = 401
            data = {
                'errors': [{
                    'details': 'Authorization Required. Request does not contain an access token',
                    'status': str(code),
                    'title': 'Unauthorized'
                }]
            }
        else:
            # Did not match a custom exception, continue normally
            return super(ExceptionAwareApi, self).handle_error(e)
        return self.make_response(data, code)

    def abort(self, code=500, message=None, **kwargs):
        '''
        Properly abort the current request.
        Raise a `HTTPException` for the given status `code`.
        Attach any keyword arguments to the exception for later processing.
        :param int code: The associated HTTP status code
        :param str message: An optional details message
        :param kwargs: Any additional data to pass to the error payload
        :raise HTTPException:
        '''
        try:
            flask.abort(code)
        except HTTPException as e:
            # JSON API specs
            kwargs['errors'] = []
            kwargs['errors'].append({})
            kwargs['errors'][0]['detail'] = message
            kwargs['errors'][0]['status'] = str(code)
            kwargs['errors'][0]['title'] = str(e).split(':')[1].lstrip(' ')
            e.data = kwargs
            raise


cors = CORS(app, resources={r'/*': {'origins': app.config['ALLOW_ORIGIN']}})
db = SQLAlchemy(app, session_options={
                'autoflush': False, 'autocommit': False, "expire_on_commit": False})
api = ExceptionAwareApi(app, doc='/doc/', title='LXC Web Panel API documentation',
                        description='https://github.com/lxc-webpanel/lxc-rest')
nslxc = api.namespace('api/v1/lxc/', description='Operations related to LXC')
nslwp = api.namespace(
    'api/v1/lwp/', description='Operations related to LXC Web Panel')
jwt = JWT(app, authenticate)

from app import handlers, models, views, routes
