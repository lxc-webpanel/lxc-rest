#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

# Users JSON fields
users_fields_put = api.model('UsersModelPut', {
    'name': fields.String,
    'email': fields.String,
    'groups': fields.List(fields.Integer(min=1)),
    'containers': fields.List(fields.Integer(min=1)),
    'password': fields.String
})

users_fields_post = api.inherit('UsersModelPost', users_fields_put, {
    'username': fields.String(required=True),
    'name': fields.String(required=True),
    'groups': fields.List(fields.Integer(min=1), required=True),
    'password': fields.String(required=True)
})

users_fields = api.inherit('UsersModel', users_fields_put, {
    'id': fields.Integer
})


# Groups JSON fields
groups_fields_put = api.model('GroupsModelPut', {
    'name': fields.String,
    'abilities': fields.List(fields.Integer(min=1)),
    'users': fields.List(fields.Integer(min=1))
})

groups_fields_post = api.inherit('GroupsModelPost', groups_fields_put, {
    'name': fields.String(required=True)
})

groups_fields = api.inherit('GroupsModel', groups_fields_put, {
    'id': fields.Integer
})


# Abilities JSON fields
abilities_fields_put = api.model('AbilitiesModelPut', {
    'groups': fields.List(fields.Integer(min=1))
})

abilities_fields = api.inherit('AbilitiesModel', abilities_fields_put, {
    'id': fields.Integer,
    'name': fields.String
})


# HostReboot JSON fields
host_reboot_fields_post = api.model('HostRebootModelPost', {
    'message': fields.String
})


containers_args_fields = api.model('ContainerArgs', {})

containers_fields_post = api.model('ContainerstModelPost', {
    'name': fields.String,
    'template': fields.String,
    'args': fields.Nested(containers_args_fields)
})


containers_fields_put = api.model('ContainerstModelPut', {
    'id': fields.Integer,
    'arch': fields.String,
    'cpu_shares': fields.Integer,
    'cpus': fields.String,
    'groups': fields.List(fields.String),
    'hostname': fields.String,
    'memory_limit': fields.Integer,
    'memory_usage': fields.Integer,
    'name': fields.String,
    'networks': fields.List(fields.String),
    'pid': fields.Integer,
    'rootfs': fields.String,
    'sorted_dict': fields.Integer,
    'start_auto': fields.Integer,
    'start_delay': fields.Integer,
    'start_order': fields.Integer,
    'state': fields.String,
    'swap_limit': fields.Integer
})