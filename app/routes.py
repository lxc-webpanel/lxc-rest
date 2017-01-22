#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app import nslxc, nslwp
from .views import *

# Users routes
nslwp.add_resource(UsersList, '/users')
nslwp.add_resource(Users, '/users/<int:id>')
nslwp.add_resource(Me, '/me')
nslwp.add_resource(GroupsList, '/groups')
nslwp.add_resource(Groups, '/groups/<int:id>')
nslwp.add_resource(AbilitiesList, '/abilities')
nslwp.add_resource(Abilities, '/abilities/<int:id>')

# LXC templates routes
# api.add_resource(LxcTemplatesList,
#                  '/api/v1/lxc/templates')
# api.add_resource(LxcTemplatesInfos,
#                  '/api/v1/lxc/templates/<string:template>')


# Containers routes
nslxc.add_resource(ContainersList,
                   '/containers')
nslxc.add_resource(Containers,
                   '/containers/<int:id>')
nslxc.add_resource(ContainersStart,
                   '/containers/<int:id>/start')
nslxc.add_resource(ContainersFreeze,
                   '/containers/<int:id>/freeze')
nslxc.add_resource(ContainersUnfreeze,
                   '/containers/<int:id>/unfreeze')
nslxc.add_resource(ContainersStop,
                   '/containers/<int:id>/stop')
nslxc.add_resource(ContainersShutdown,
                   '/containers/<int:id>/shutdown')
nslxc.add_resource(ContainersRestart,
                   '/containers/<int:id>/restart')

# lxc-chekconfig route
nslxc.add_resource(LxcCheckConfig, '/checkconfig')

# Host routes
nslwp.add_resource(HostStats, '/host')
nslwp.add_resource(HostReboot, '/host/reboot')
