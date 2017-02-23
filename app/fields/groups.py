#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api


groups_fields_attributes = api.model('GroupsFieldsAttributes', {
    'name': fields.String
})

groups_fields_attributes_post = api.model('GroupsFieldsAttributesPost', {
    'name': fields.String(required=True, pattern='^(?!\s*$).+')
})

groups_fields = api.model('GroupsFields', {
    'type': fields.String,
    'id': fields.Integer,
    'attributes': fields.Nested(groups_fields_attributes),
})

from .users import *
from .abilities import *

groups_fields_with_relationships = api.model('GroupsFieldsWithRelationships', {
    'relationships': fields.Nested(api.model('GroupsRelationships', {
        'users': fields.Nested(api.model('GroupsData', {
            'data': fields.Nested(api.models['UsersFields'], as_list=True)
        })),
        'abilities': fields.Nested(api.model('ContainersData', {
            'data': fields.Nested(api.models['AbilitiesFields'], as_list=True)
        }))
    }))
})

groups_fields_with_relationships_post_put = api.model('GroupsFieldsWithRelationshipsPost', {
    'relationships': fields.Nested(api.model('GroupsRelationshipsPost', {
        'users': fields.Nested(api.model('GroupsDataPost', {
            'data': fields.Nested(api.model('GroupsPostData', {
                'type': fields.String,
                'id': fields.Integer
            }), as_list=True)
        })),
        'abilities': fields.Nested(api.model('ContainersDataPost', {
            'data': fields.Nested(api.model('ContainersPostData', {
                'type': fields.String,
                'id': fields.Integer
            }), as_list=True)
        }))
    }))
})

groups_fields_get = api.inherit('GroupsFieldsGet', groups_fields_with_relationships, {
    'type': fields.String,
    'id': fields.Integer,
    'attributes': fields.Nested(groups_fields_attributes),
})

groups_fields_post = api.inherit('GroupsFieldsPost', groups_fields_with_relationships_post_put, {
    'type': fields.String(pattern='groups'),
    'attributes': fields.Nested(groups_fields_attributes_post),
})

groups_fields_put = api.inherit('GroupsFieldsPut', groups_fields_with_relationships_post_put, {
    'type': fields.String(pattern='groups'),
    'attributes': fields.Nested(groups_fields_attributes),
})
