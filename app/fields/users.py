#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields, Model
from app import api


users_fields_attributes = api.model('UsersFieldsAttributes', {
    'admin': fields.Boolean(default=False),
    'username': fields.String,
    'name': fields.String,
    'email': fields.String,
    'registered_on': fields.DateTime(dt_format='rfc822')
})

users_fields_attributes_post = api.model('UsersFieldsAttributesPost', {
    'admin': fields.Boolean(default=False),
    'username': fields.String(required=True, pattern='^(?!\s*$).+'),
    'name': fields.String(required=True, pattern='^(?!\s*$).+'),
    'email': fields.String(pattern=r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'),
    'password': fields.String(required=True, pattern='^(?!\s*$).+')
})

users_fields_attributes_put = api.model('UsersFieldsAttributesPut', {
    'admin': fields.Boolean,
    'name': fields.String(pattern='^(?!\s*$).+'),
    'email': fields.String(pattern=r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'),
    'password': fields.String(pattern='^(?!\s*$).+')
})

users_fields_with_relationships_post_put = api.model('UsersFieldsWithRelationshipsPost', {
    'relationships': fields.Nested(api.model('UsersRelationshipsPost', {
        'groups': fields.Nested(api.model('GroupsDataPost', {
            'data': fields.Nested(api.model('GroupsPostData', {
                'type': fields.String(pattern='groups'),
                'id': fields.Integer
            }), as_list=True)
        })),
        'containers': fields.Nested(api.model('ContainersDataPost', {
            'data': fields.Nested(api.model('ContainersPostData', {
                'type': fields.String(pattern='containers'),
                'id': fields.Integer
            }), as_list=True)
        }))
    }))
})

_users_fields_get = api.inherit('UsersFieldsGet', users_fields_with_relationships_post_put, {
    'type': fields.String,
    'id': fields.Integer,
    'attributes': fields.Nested(users_fields_attributes),
})

_users_fields_post = api.inherit('UsersFieldsPost', users_fields_with_relationships_post_put, {
    'type': fields.String(pattern='users'),
    'attributes': fields.Nested(users_fields_attributes_post),
})

_users_fields_put = api.inherit('UsersFieldsPut', users_fields_with_relationships_post_put, {
    'type': fields.String(pattern='users'),
    'attributes': fields.Nested(users_fields_attributes_put),
})


users_fields_get = api.model('UsersRootGet', { 'data': fields.Nested(_users_fields_get) })
users_fields_post = api.model('UsersRootPost', { 'data': fields.Nested(_users_fields_post) })
users_fields_put = api.model('UsersRootPut', { 'data': fields.Nested(_users_fields_put) })
