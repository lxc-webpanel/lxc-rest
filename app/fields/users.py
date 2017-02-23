#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields, Model
from app import api


users_fields_attributes = api.model('UsersFieldsAttributes', {
    'admin': fields.Boolean(default=False),
    'username': fields.String,
    'name': fields.String,
    'email': fields.String
})

users_fields_attributes_post = api.model('UsersFieldsAttributesPost', {
    'admin': fields.Boolean(default=False),
    'username': fields.String(required=True, pattern='^(?!\s*$).+'),
    'name': fields.String(required=True, pattern='^(?!\s*$).+'),
    'email': fields.String(pattern=r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'),
    'password': fields.String(required=True, pattern='^(?!\s*$).+')
})

users_fields = api.model('UsersFields', {
    'type': fields.String(pattern='users'),
    'id': fields.Integer,
    'attributes': fields.Nested(users_fields_attributes),
})

from .groups import *
from .containers import *

users_fields_with_relationships = api.model('UsersFieldsWithRelationships', {
    'relationships': fields.Nested(api.model('UsersRelationships', {
        'groups': fields.Nested(api.model('GroupsData', {
            'data': fields.Nested(api.models['GroupsFields'], as_list=True)
        })),
        'containers': fields.Nested(api.model('ContainersData', {
            'data': fields.Nested(api.models['ContainersFields'], as_list=True)
        }))
    }))
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

users_fields_get = api.inherit('UsersFieldsGet', users_fields_with_relationships, {
    'type': fields.String,
    'id': fields.Integer,
    'attributes': fields.Nested(users_fields_attributes),
})

users_fields_post = api.inherit('UsersFieldsPost', users_fields_with_relationships_post_put, {
    'type': fields.String(pattern='users'),
    'attributes': fields.Nested(users_fields_attributes_post),
})

users_fields_put = api.inherit('UsersFieldsPut', users_fields_with_relationships_post_put, {
    'type': fields.String(pattern='users'),
    'attributes': fields.Nested(users_fields_attributes),
})
