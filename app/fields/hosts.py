#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api


host_stats_fields_attributes = api.model('HostStats', {
    'uptime': fields.Nested(api.model('HostUptime', {
        'days': fields.Integer,
        'hours': fields.Integer,
        'minutes': fields.Integer,
        'seconds': fields.Integer
    })),
    'hostname': fields.String,
    'distrib': fields.String,
    'disk': fields.Nested(api.model('HostDiskUsage', {
        'name': fields.String,
        'total': fields.Integer,
        'used': fields.Integer,
        'free': fields.Integer,
        'percent': fields.Float
    }), as_list=True),
    'cpu': fields.Nested(api.model('HostCpuUsage', {
        'usage': fields.Float,
        'model': fields.String,
        'logical': fields.Integer,
        'physical': fields.Integer
    })),
    'memory': fields.Nested(api.model('HostMemoryUsage', {
        'virtual': fields.Nested(api.model('HostMemoryVirtual', {
            'total': fields.Integer,
            'percent': fields.Float,
            'free': fields.Integer,
            'used': fields.Integer
        })),
        'swap': fields.Nested(api.model('HostMemorySwap', {
            'total': fields.Integer,
            'percent': fields.Float,
            'free': fields.Integer,
            'used': fields.Integer
        }))
    })),
    'kernel': fields.String
})

_host_stats_fields_get = api.model('HostStatsFieldsGet', {
    'type': fields.String,
    'attributes': fields.Nested(host_stats_fields_attributes),
})


host_stats_fields_get = api.model('HostStatsRootGet', { 'data': fields.Nested(_host_stats_fields_get) })


host_reboot_fields_post = api.model('HostRebootModelPost', {
    'message': fields.String
})
