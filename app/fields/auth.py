#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

auth_fields_get = api.model('AuthGet', { 'access_token': fields.String })
auth_fields_post = api.model('AuthPost', {
	'username': fields.String(required=True),
	'password': fields.String(required=True)
	}
)
