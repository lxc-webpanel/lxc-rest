#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api


host_stats_get = api.model('HostStats', {
    'uptime': fields.Nested(api.model('HostUptime', {
        'days': fields.Integer,
        'hours': fields.Integer,
        'minutes': fields.Integer,
        'seconds': fields.Integer
    })),
    'hostname': fields.String,
    'dist': fields.String,
    'disk': fields.Nested(api.model('HostDiskUsage', {
        'disk': fields.String,
        'total': fields.Integer,
        'used': fields.Integer,
        'free': fields.Integer,
        'percent': fields.Integer
    })),
    'cpu': fields.Nested(api.model('HostCpuUsage', {
        'usage': fields.Integer,
        'model': fields.String,
        'cores': fields.String
    })),
    'memory': fields.Nested(api.model('HostMemoryUsage', {
        'percent': fields.Integer,
        'percent_cached': fields.Integer,
        'swap_percent': fields.Integer,
        'swap_used': fields.Integer,
        'swap_total': fields.Integer,
        'used': fields.Integer,
        'total': fields.Integer
    })),
    'kernel': fields.String
})

host_reboot_fields_post = api.model('HostRebootModelPost', {
    'message': fields.String
})
