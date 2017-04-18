#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import timedelta

SSL = False
# Easy way : make-ssl-cert generate-default-snakeoil --force-overwrite
SSL_CERT = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
SSL_KEY = '/etc/ssl/private/ssl-cert-snakeoil.key'


DEBUG = False
SECRET_KEY = u'ça cest une vrai appli ! il faut que la clé soit bien longue'
SQLALCHEMY_DATABASE_URI = 'sqlite:///../lxc-webpanel.sqlite'
SQLALCHEMY_COMMIT_ON_TEARDOWN = False
SQLALCHEMY_TRACK_MODIFICATIONS = False

JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
JWT_HEADER_TYPE = 'Bearer'

SWAGGER_UI_DOC_EXPANSION = 'list' # none, list or full

ALLOW_ORIGIN = '*' # CORS
