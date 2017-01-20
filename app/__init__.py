#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restplus import Api
from flask_jwt import JWT
from flask_cors import CORS

app = Flask(__name__, instance_relative_config=True,
            template_folder='../templates')


# Load the default configuration
app.config.from_object('config.default')

# Load the configuration from the instance folder
try:
    app.config.from_pyfile('config.py')
except IOError:
    pass

# Load the file specified by the APP_CONFIG_FILE environment variable
# Variables defined here will override those in the default configuration
try:
    app.config.from_envvar('LWP_CONFIG_FILE')
except RuntimeError:
    pass


def authenticate(username, password):
    user = User.query.filter_by(username=username).first()

    if not user or not user.verify_password(password):
        return False

    return user


cors = CORS(app, resources={r'/*': {'origins': app.config['ALLOW_ORIGIN']}})
db = SQLAlchemy(app, session_options={
                'autoflush': False, 'autocommit': False, "expire_on_commit": False})
api = Api(app, doc='/doc/', title='LXC Web Panel API documentation',
          description='https://github.com/')
nslxc = api.namespace('api/v1/lxc/', description='Operations related to LXC')
nslwp = api.namespace(
    'api/v1/lwp/', description='Operations related to LXC Web Panel')
jwt = JWT(app, authenticate)

from app import handlers, models, views, routes
