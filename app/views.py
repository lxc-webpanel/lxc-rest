#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import request
from flask_restplus import Resource, reqparse
from flask_restplus.reqparse import Argument, RequestParser
from flask_jwt import jwt_required, current_identity
from app import db, api
from .models import *
from .fields import *
from .decorators import *
import lwp
import lxc
import os.path
import platform
import re
import gzip
import socket
import subprocess
import json


users_list_parser = api.parser()
users_list_parser.add_argument(
    'username', type=str, required=True, location='json')
users_list_parser.add_argument(
    'name', type=str, required=True, location='json')
users_list_parser.add_argument('email', type=str, location='json')
users_list_parser.add_argument(
    'groups', type=list, required=True, location='json')
users_list_parser.add_argument('containers', type=list, location='json')
users_list_parser.add_argument(
    'password', type=str, required=True, location='json')


class UsersList(Resource):
    decorators = [jwt_required()]

    @user_has('users_infos_all')
    @api.marshal_with(users_fields, envelope='data')
    def get(self):
        """
        Get users list
        """
        return User.query.all()

    @user_has('users_create')
    @api.expect(users_fields_post)
    @api.marshal_with(users_fields, envelope='data')
    def post(self):
        """
        Create user
        """
        args = users_list_parser.parse_args()

        if User.query.filter_by(username=args.username).first():
            return {'errors': 'User already exists'}, 409

        user = User()

        user.username = args.username
        user.name = args.name
        user.groups = args.groups

        if args.email:
            user.email = args.email
        if args.containers:
            user.containers = args.containers

        user.hash_password(args.password)

        db.session.add(user)
        db.session.commit()

        return user, 201


users_parser = api.parser()
users_parser.add_argument('name', type=str, location='json')
users_parser.add_argument('email', type=str, location='json')
users_parser.add_argument('groups', type=list, location='json')
users_parser.add_argument('containers', type=list, location='json')
users_parser.add_argument('password', type=str, location='json')


class Users(Resource):
    decorators = [jwt_required()]

    @user_has('users_infos')
    @api.marshal_with(users_fields, envelope='data')
    def get(self, id):
        """
        Get user
        """
        user = User.query.get(id)

        if not user:
            return {'errors': "User not found"}, 404

        return user

    @user_has('users_update')
    @api.expect(users_fields_put)
    @api.marshal_with(users_fields, envelope='data')
    def put(self, id):
        """
        Update user
        """
        user = User.query.get(id)

        if not user:
            return {'errors': "User not found"}, 404

        args = users_parser.parse_args()

        if args.name:
            user.name = args.name
        if args.email:
            user.email = args.email
        if args.groups:
            user.groups = args.groups
        if args.containers:
            user.containers = args.containers
        if args.password:
            user.hash_password(args.password)

        if len(args) > 0:
            db.session.commit()

        return user

    @user_has('users_delete')
    def delete(self, id):
        """
        Delete user
        """
        user = User.query.get(id)

        if not user:
            return {'errors': "User not found"}, 404

        db.session.delete(user)
        db.session.commit()

        return {'message': 'User %s deleted' % user.name}, 200


class Me(Resource):
    decorators = [jwt_required()]

    @api.marshal_with(users_fields, envelope='data')
    def get(self):
        """
        Get me
        """
        return current_identity

    @user_has('me_edit')
    @api.expect(users_fields_put)
    @api.marshal_with(users_fields, envelope='data')
    def put(self):
        """
        Update me
        """
        user = User.query.get(current_identity.id)

        args = users_parser.parse_args()

        if args.name:
            user.name = args.name
        if args.email:
            user.email = args.email
        if args.groups:
            user.groups = args.groups
        if args.containers:
            user.containers = args.containers
        if args.password:
            user.hash_password(args.password)

        if len(args) > 0:
            db.session.commit()

        return user

    @user_has('me_edit')
    def delete(self):
        """
        Delete me (stupid)
        """
        user = User.query.get(current_identity.id)

        db.session.delete(user)
        db.session.commit()

        return {'message': 'User %s deleted' % user.name}, 200


groups_list_parser = api.parser()
groups_list_parser.add_argument(
    'name', type=str, required=True, location='json')
groups_list_parser.add_argument('abilities', type=list, location='json')
groups_list_parser.add_argument('users', type=list, location='json')


class GroupsList(Resource):
    decorators = [jwt_required()]

    @user_has('groups_infos_all')
    @api.marshal_with(groups_fields, envelope='data')
    def get(self):
        """
        Get groups list
        """
        return Group.query.all()

    @user_has('groups_create')
    @api.expect(groups_fields_post)
    @api.marshal_with(groups_fields, envelope='data')
    def post(self):
        """
        Create group
        """
        args = groups_list_parser.parse_args()

        group = Group(name=args.name)

        if args.abilities:
            group.abilities = args.abilities
        if args.users:
            group.users = args.users

        db.session.add(group)
        db.session.commit()

        return group, 201


groups_parser = api.parser()
groups_parser.add_argument('name', type=str, location='json')
groups_parser.add_argument('abilities', type=list, location='json')
groups_parser.add_argument('users', type=list, location='json')


class Groups(Resource):
    decorators = [jwt_required()]

    @user_has('groups_infos')
    @api.marshal_with(groups_fields, envelope='data')
    def get(self, id):
        """
        Get group
        """
        group = Group.query.get(id)

        if not group:
            return {'errors': "Group not found"}, 404

        return group

    @user_has('groups_update')
    @api.expect(groups_fields_put)
    @api.marshal_with(groups_fields, envelope='data')
    def put(self, id):
        """
        Update group
        """
        group = Group.query.get(id)

        args = groups_parser.parse_args()

        if args.name:
            group.name = args.name
        if args.abilities:
            group.abilities = args.abilities
        if args.users:
            group.users = args.users

        if len(args) > 0:
            db.session.commit()

        return group

    @user_has('groups_delete')
    def delete(self, id):
        """
        Delete group
        """
        group = Group.query.get(id)

        if not group:
            return {'errors': 'Group not found'}, 404

        db.session.delete(group)
        db.session.commit()

        return {'message': 'Group %s deleted' % group.name}, 200


class AbilitiesList(Resource):
    decorators = [jwt_required()]

    @user_has('abilities_infos_all')
    @api.marshal_with(abilities_fields, envelope='data')
    def get(self):
        """
        Get abilities list
        """
        return Ability.query.all()


abilities_parser = api.parser()
abilities_parser.add_argument('groups', type=list, location='json')


class Abilities(Resource):
    decorators = [jwt_required()]

    @user_has('abilities_infos')
    @api.marshal_with(abilities_fields, envelope='data')
    def get(self, id):
        """
        Get ability
        """
        ability = Ability.query.get(id)

        if not ability:
            return {'errors': "Ability not found"}, 404

        return ability

    @user_has('abilities_update')
    @api.expect(abilities_fields_put)
    @api.marshal_with(abilities_fields, envelope='data')
    def put(self, id):
        """
        Update ability
        """
        ability = Ability.query.get(id)

        args = abilities_parser.parse_args()

        if args.groups:
            ability.groups = args.groups

        if len(args) > 0:
            db.session.commit()

        return ability

###########
# LXC API #
###########


# class LxcTemplatesList(Resource):
#     decorators = [jwt_required()]

#     @user_has('lxc_infos')
#     def get(self):
#         return {'templates': lwp.get_templates_list()}, 200


# class LxcTemplatesInfos(Resource):
#     decorators = [jwt_required()]

#     @user_has('lxc_infos')
#     def get(self, template):
#         return lwp.get_template_options(template), 200


##################
# Containers API #
##################
class ContainersList(Resource):
    decorators = [jwt_required()]

    @user_has('ct_infos')
    @api.marshal_with(containers_fields, envelope='data')
    def get(self):
        """
        Get containers list
        """
        containers = []

        for c in lxc.list_containers():
            container = Container.query.filter_by(name=c).first()
            if container.id in current_identity.containers:
                infos = lwp.ct_infos(c, id=container.id)
                containers.append(infos)

        return containers

    @user_has('ct_create')
    @api.expect(containers_fields_post)
    @api.marshal_with(containers_fields_post, envelope='data')
    @api.doc(responses={
        201: 'Container created',
        409: 'Container already exists',
        500: 'Can\'t create container'
    })
    def post(self):
        """
        Create container
        """
        data = request.get_json()

        c = lxc.Container(data['name'])

        if 'name' in data:
            if not c.defined:
                try:
                    if not isinstance(data['template']['args'], str):
                        data['template']['args'] = ''
                except KeyError:
                    data['template']['args'] = ''
                if not c.create(template=data['template']['name'], flags=lxc.LXC_CREATE_QUIET, args=data['template']['args'], bdevtype=None):
                    return {}, 500

                # Add container to database
                container = Container(name=data['name'])
                db.session.add(container)
                db.session.commit()
                # Get container ID
                container = Container.query.filter_by(
                    name=data['name']).first()
                # Add container to allowed user's containers
                user = User.query.get(current_identity.id)
                user.containers.append(container.id)
                db.session.commit()

                return Containers.put(self, container.id, d=data), 201
            return {}, 409


class Containers(Resource):
    decorators = [jwt_required()]

    @user_has('ct_infos')
    @api.marshal_with(containers_fields, envelope='data')
    def get(self, id):
        """
        Get container
        """
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and id in current_identity.containers:
            response = lwp.ct_infos(container.name, id=id)
            return response

        return {'errors': 'Container doesn\'t exists!'}, 404

    @user_has('ct_update')
    @api.expect(containers_fields_put)
    @api.marshal_with(containers_fields_put, envelope='data')
    def put(self, id, d=None):
        """
        Update container
        """
        def set_config(container, config_item, config_value):
            if container.set_config_item(config_item, config_value):
                container.save_config()
            else:
                return 500

        # Get data from ContainersList.post()
        # or
        # from Containers.put()
        if d:
            data = d
        else:
            data = request.get_json()

        container = Container.query.get(id)

        c = lxc.Container(container.name)

        if 'name' in data:
            if data['name'] != c.name:
                if not c.rename(data['name']):
                    return 500

        c = lxc.Container(data['name'])

        if 'lxc' in data:
            if 'aa_allow_incomplete' in data['lxc']:
                set_config(c, 'lxc.aa_allow_incomplete', data[
                           'lxc']['aa_allow_incomplete'])
            if 'aa_profile' in data['lxc']:
                set_config(c, 'lxc.aa_profile', data['lxc']['aa_profile'])
            if 'arch' in data['lxc']:
                set_config(c, 'lxc.arch', data['lxc']['arch'])
            if 'autodev' in data['lxc']:
                set_config(c, 'lxc.autodev', data['lxc']['autodev'])
            if 'cap' in data['lxc']:
                if 'drop' in data['lxc']['cap']:
                    set_config(c, 'lxc.cap.drop', data['lxc']['cap']['drop'])
                if 'keep' in data['lxc']['cap']:
                    set_config(c, 'lxc.cap.keep', data['lxc']['cap']['keep'])
            if 'cgroup' in data['lxc']:
                if 'memory' in data['lxc']['cgroup']:
                    if 'limit_in_bytes' in data['lxc']['cgroup']['memory']:
                        set_config(c, 'lxc.cgroup.memory.limit_in_bytes', data[
                                   'lxc']['cgroup']['memory']['limit_in_bytes'])
                    if 'memsw' in data['lxc']['cgroup']['memory']:
                        if 'limit_in_bytes' in data['lxc']['cgroup']['memory']['memsw']:
                            set_config(c, 'lxc.cgroup.memory.memsw.limit_in_bytes', data[
                                       'lxc']['cgroup']['memory']['memsw']['limit_in_bytes'])
                if 'cpu' in data['lxc']['cgroup']:
                    if 'shares' in data['lxc']['cgroup']['cpu']:
                        set_config(c, 'lxc.cgroup.cpu.shares', data[
                                   'lxc']['cgroup']['cpu']['shares'])
                if 'cpuset' in data['lxc']['cgroup']:
                    if 'cpus' in data['lxc']['cgroup']['cpuset']:
                        set_config(c, 'lxc.cgroup.cpuset.cpus', data[
                                   'lxc']['cgroup']['cpuset']['cpus'])
            if 'console' in data['lxc']:
                if '_' in data['lxc']['console']:
                    set_config(c, 'lxc.console', data['lxc']['console']['_'])
                if 'logfile' in data['lxc']['console']:
                    set_config(c, 'lxc.console.logfile', data[
                               'lxc']['console']['logfile'])
            if 'devttydir' in data['lxc']:
                set_config(c, 'lxc.devttydir', data['lxc']['devttydir'])
            if 'environment' in data['lxc']:
                set_config(c, 'lxc.environment', data['lxc']['environment'])
            if 'ephemeral' in data['lxc']:
                set_config(c, 'lxc.ephemeral', data['lxc']['ephemeral'])
            if 'group' in data['lxc']:
                set_config(c, 'lxc.group', data['lxc']['group'])
            if 'haltsignal' in data['lxc']:
                set_config(c, 'lxc.haltsignal', data['lxc']['haltsignal'])
            if 'hook' in data['lxc']:
                if 'autodev' in data['lxc']['hook']:
                    set_config(c, 'lxc.hook.autodev', data[
                               'lxc']['hook']['autodev'])
                if 'clone' in data['lxc']['hook']:
                    set_config(c, 'lxc.hook.clone', data[
                               'lxc']['hook']['clone'])
                if 'destroy' in data['lxc']['hook']:
                    set_config(c, 'lxc.hook.destroy', data[
                               'lxc']['hook']['destroy'])
                if 'mount' in data['lxc']['hook']:
                    set_config(c, 'lxc.hook.mount', data[
                               'lxc']['hook']['mount'])
                if 'post-stop' in data['lxc']['hook']:
                    set_config(c, 'lxc.hook.post-stop',
                               data['lxc']['hook']['post-stop'])
                if 'pre-mount' in data['lxc']['hook']:
                    set_config(c, 'lxc.hook.pre-mount',
                               data['lxc']['hook']['pre-mount'])
                if 'pre-start' in data['lxc']['hook']:
                    set_config(c, 'lxc.hook.pre-start',
                               data['lxc']['hook']['pre-start'])
                if 'start' in data['lxc']['hook']:
                    set_config(c, 'lxc.hook.start', data[
                               'lxc']['hook']['start'])
                if 'stop' in data['lxc']['hook']:
                    set_config(c, 'lxc.hook.stop', data['lxc']['hook']['stop'])
            if 'id_map' in data['lxc']:
                set_config(c, 'lxc.id_map', data['lxc']['id_map'])
            if 'include' in data['lxc']:
                set_config(c, 'lxc.include', data['lxc']['include'])
            if 'init_cmd' in data['lxc']:
                set_config(c, 'lxc.init_cmd', data['lxc']['init_cmd'])
            if 'init_gid' in data['lxc']:
                set_config(c, 'lxc.init_gid', data['lxc']['init_gid'])
            if 'init_uid' in data['lxc']:
                set_config(c, 'lxc.init_uid', data['lxc']['init_uid'])
            if 'kmsg' in data['lxc']:
                set_config(c, 'lxc.kmsg', data['lxc']['kmsg'])
            if 'logfile' in data['lxc']:
                set_config(c, 'lxc.logfile', data['lxc']['logfile'])
            if 'loglevel' in data['lxc']:
                set_config(c, 'lxc.loglevel', data['lxc']['loglevel'])
            if 'monitor' in data['lxc']:
                if 'unshare' in data['lxc']['monitor']:
                    set_config(c, 'lxc.monitor.unshare', data[
                               'lxc']['monitor']['unshare'])
            if 'mount' in data['lxc']:
                if '_' in data['lxc']['mount']:
                    set_config(c, 'lxc.mount', data['lxc']['mount']['_'])
                if 'auto' in data['lxc']['mount']:
                    set_config(c, 'lxc.mount.auto', data[
                               'lxc']['mount']['auto'])
                if 'entry' in data['lxc']['mount']:
                    set_config(c, 'lxc.mount.entry', data[
                               'lxc']['mount']['entry'])
            if 'network' in data['lxc']:
                for i in range(len(data['lxc']['network'])):
                    if 'type' in data['lxc']['network']:
                        set_config(c, 'lxc.network.%s.type' %
                                   i, data['lxc']['network']['type'])
                    if 'veth' in data['lxc']['network']:
                        if 'pair' in data['lxc']['network']['veth']:
                            set_config(c, 'lxc.network.%s.veth.pair' %
                                       i, data['lxc']['network']['veth']['pair'])
                    if 'vlan' in data['lxc']['network']:
                        if 'id' in data['lxc']['network']['vlan']:
                            set_config(c, 'lxc.network.%s.vlan.id' %
                                       i, data['lxc']['network']['vlan']['id'])
                    if 'macvlan' in data['lxc']['network']:
                        if 'mode' in data['lxc']['network']['macvlan']:
                            set_config(c, 'lxc.network.%s.macvlan.mode' % i, data[
                                       'lxc']['network']['macvlan']['mode'])
                    if 'flags' in data['lxc']['network']:
                        set_config(c, 'lxc.network.%s.flags' %
                                   i, data['lxc']['network']['flags'])
                    if 'link' in data['lxc']['network']:
                        set_config(c, 'lxc.network.%s.link' %
                                   i, data['lxc']['network']['link'])
                    if 'mtu' in data['lxc']['network']:
                        set_config(c, 'lxc.network.%s.mtu' %
                                   i, data['lxc']['network']['mtu'])
                    if 'name' in data['lxc']['network']:
                        set_config(c, 'lxc.network.%s.name' %
                                   i, data['lxc']['network']['name'])
                    if 'hwaddr' in data['lxc']['network']:
                        set_config(c, 'lxc.network.%s.hwaddr' %
                                   i, data['lxc']['network']['hwaddr'])
                    if 'ipv4' in data['lxc']['network']:
                        if '_' in data['lxc']['network']['ipv4']:
                            set_config(c, 'lxc.network.%s.ipv4' %
                                       i, data['lxc']['network']['ipv4']['_'])
                        if 'gateway' in data['lxc']['network']['ipv4']:
                            set_config(c, 'lxc.network.%s.ipv4.gateway' % i, data[
                                       'lxc']['network']['ipv4']['gateway'])
                    if 'ipv6' in data['lxc']['network']:
                        if '_' in data['lxc']['network']['ipv6']:
                            set_config(c, 'lxc.network.%s.ipv6' %
                                       i, data['lxc']['network']['ipv6']['_'])
                        if 'gateway' in data['lxc']['network']['ipv6']:
                            set_config(c, 'lxc.network.%s.ipv6.gateway' % i, data[
                                       'lxc']['network']['ipv6']['gateway'])
                    if 'script' in data['lxc']['network']:
                        if 'up' in data['lxc']['network']['script']:
                            set_config(c, 'lxc.network.%s.script.up' %
                                       i, data['lxc']['network']['script']['up'])
                        if 'down' in data['lxc']['network']['script']:
                            set_config(c, 'lxc.network.%s.script.down' % i, data[
                                       'lxc']['network']['script']['down'])
            if 'no_new_privs' in data['lxc']:
                set_config(c, 'lxc.no_new_privs', data['lxc']['no_new_privs'])
            if 'pts' in data['lxc']:
                set_config(c, 'lxc.pts', data['lxc']['pts'])
            if 'rebootsignal' in data['lxc']:
                set_config(c, 'lxc.rebootsignal', data['lxc']['rebootsignal'])
            if 'rootfs' in data['lxc']:
                if '_' in data['lxc']['rootfs']:
                    set_config(c, 'lxc.rootfs', data['lxc']['rootfs']['_'])
                if 'mount' in data['lxc']['rootfs']:
                    set_config(c, 'lxc.rootfs.mount', data[
                               'lxc']['rootfs']['mount'])
                if 'options' in data['lxc']['rootfs']:
                    set_config(c, 'lxc.rootfs.options', data[
                               'lxc']['rootfs']['options'])
                if 'backend' in data['lxc']['rootfs']:
                    set_config(c, 'lxc.rootfs.backend', data[
                               'lxc']['rootfs']['backend'])
            if 'se_context' in data['lxc']:
                set_config(c, 'lxc.se_context', data['lxc']['se_context'])
            if 'seccomp' in data['lxc']:
                set_config(c, 'lxc.seccomp', data['lxc']['seccomp'])
            if 'start' in data['lxc']:
                if 'auto' in data['lxc']['start']:
                    set_config(c, 'lxc.start.auto', data[
                               'lxc']['start']['auto'])
                if 'delay' in data['lxc']['start']:
                    set_config(c, 'lxc.start.delay', data[
                               'lxc']['start']['delay'])
                if 'order' in data['lxc']['start']:
                    set_config(c, 'lxc.start.order', data[
                               'lxc']['start']['order'])
            if 'stopsignal' in data['lxc']:
                set_config(c, 'lxc.stopsignal', data['lxc']['stopsignal'])
            if 'syslog' in data['lxc']:
                set_config(c, 'lxc.syslog', data['lxc']['syslog'])
            if 'tty' in data['lxc']:
                set_config(c, 'lxc.tty', data['lxc']['tty'])
            if 'utsname' in data['lxc']:
                set_config(c, 'lxc.utsname', data['lxc']['utsname'])

            return Containers.get(self, container.id)

        return {'errors': 'Container %s doesn\'t exists!' % container}, 404

    @user_has('ct_delete')
    @api.doc(responses={
        200: 'Container destroyed',
        404: 'Container doesn\'t exists',
        409: 'Can\'t destroy and/or stop container',
        500: 'Can\'t create container'
    })
    def delete(self, id):
        """
        Destroy container
        """
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and id in current_identity.containers:
            if c.running:
                if not c.stop():
                    return 409
            if not c.destroy():
                return 409
            return 200
        return 404


class ContainersStart(Resource):
    decorators = [jwt_required()]

    @user_has('ct_start')
    def post(self, id):
        """
        Start container
        """
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and id in current_identity.containers:
            c.start()
            c.wait('RUNNING', 3)
            return 200

        return 404


class ContainersFreeze(Resource):
    decorators = [jwt_required()]

    @user_has('ct_freeze')
    def post(self, id):
        """
        Freeze container
        """
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and id in current_identity.containers:
            c.freeze()
            c.wait('FROZEN', 3)
            return 200

        return 404


class ContainersUnfreeze(Resource):
    decorators = [jwt_required()]

    @user_has('ct_unfreeze')
    def post(self, id):
        """
        Unfreeze container
        """
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and id in current_identity.containers:
            c.unfreeze()
            c.wait('RUNNING', 3)
            return 200

        return 404


class ContainersStop(Resource):
    decorators = [jwt_required()]

    @user_has('ct_stop')
    def post(self, id):
        """
        Stop container
        """
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and id in current_identity.containers:
            c.stop()
            c.wait('STOPPED', 3)
            return 200

        return 404


class ContainersShutdown(Resource):
    decorators = [jwt_required()]

    @user_has('ct_stop')
    def post(self, id):
        """
        Shutdown container
        """
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and id in current_identity.containers:
            c.shutdown(10)
            c.wait('STOPPED', 3)
            return 200

        return 404


class ContainersRestart(Resource):
    decorators = [jwt_required()]

    @user_has('ct_restart')
    def post(self, id):
        """
        Restart container
        """
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and id in current_identity.containers:
            ContainersStop.post(self, id)
            ContainersStart.post(self, id)
            return 200

        return 404


class LxcCheckConfig(Resource):
    decorators = [jwt_required()]

    @user_has('lxc_infos')
    def get(self):
        """
        Check LXC configuration (lxc-checkconfig)
        """
        config = '/proc/config.gz'

        def is_set(config_name):
            if config.endswith('.gz'):
                config_file = gzip.open(config, 'r')
            else:
                config_file = open(config, 'r')

            for line in config_file:
                if re.match('%s=[y|m]' % config_name, line):
                    return True

        def is_enabled(config_name, mandatory=None):
            if is_set(config_name):
                return 'enabled'
            else:
                if mandatory == True:
                    return 'required'
                else:
                    return 'missing'

        kver = platform.uname()[2]
        kver_split = kver.split('.')
        kver_major = int(kver_split[0])
        kver_minor = int(kver_split[1])

        if not os.path.isfile(config):
            headers_config = '/lib/modules/%s/build/.config' % kver
            boot_config = '/boot/config-%s' % kver

            if os.path.isfile(headers_config):
                config = headers_config

            if os.path.isfile(boot_config):
                config = boot_config

        config_dict = {}

        config_dict['namespaces'] = is_enabled('CONFIG_NAMESPACES', True)
        config_dict['utsname_namespace'] = is_enabled('CONFIG_UTS_NS')
        config_dict['ipc_namespace'] = is_enabled('CONFIG_IPC_NS', True)
        config_dict['pid_namespace'] = is_enabled('CONFIG_PID_NS', True)
        config_dict['user_namespace'] = is_enabled('CONFIG_USER_NS')
        config_dict['network_namespace'] = is_enabled('CONFIG_NET_NS')
        config_dict[
            'multiple_/dev/pts_instances'] = is_enabled('CONFIG_DEVPTS_MULTIPLE_INSTANCES')
        config_dict['cgroup'] = is_enabled('CONFIG_CGROUPS', True)
        config_dict['cgroup_namespace'] = is_enabled('CONFIG_CGROUP_NS', True)
        config_dict['cgroup_device'] = is_enabled('CONFIG_CGROUP_DEVICE')
        config_dict['cgroup_sched'] = is_enabled('CONFIG_CGROUP_SCHED')
        config_dict['cgroup_cpu_account'] = is_enabled('CONFIG_CGROUP_CPUACCT')

        if kver_major >= 3 and kver_minor >= 6:
            config_dict['cgroup_memory_controller'] = is_enabled(
                'CONFIG_MEMCG')
        else:
            config_dict['cgroup_memory_controller'] = is_enabled(
                'CONFIG_CGROUP_MEM_RES_CTLR')

        if is_set('CONFIG_SMP'):
            config_dict['cgroup_cpuset'] = is_enabled('CONFIG_CPUSETS')

        config_dict['veth_pair_device'] = is_enabled('CONFIG_VETH')
        config_dict['macvlan'] = is_enabled('CONFIG_MACVLAN')
        config_dict['vlan'] = is_enabled('CONFIG_VLAN_8021Q')

        if kver_major == 2 and kver_minor < 33:
            config_dict['file_capabilities'] = is_enabled(
                'CONFIG_SECURITY_FILE_CAPABILITIES')
        if (kver_major == 2 and kver_minor > 32) or kver_major > 2:
            config_dict['file_capabilities'] = 'enabled'

        return {'data': config_dict}


class HostStats(Resource):
    decorators = [jwt_required()]

    @user_has('host_stats')
    def get(self):
        """
        Get host stats (uptime, cpu, ram, etc)
        """
        os = platform.dist()
        os_str = ' '.join(os)
        host_cpu_infos = lwp.host_cpu_infos()

        return {'data': dict(
            uptime=lwp.host_uptime(),
            hostname=socket.gethostname(),
            dist=os_str,
            disk=lwp.host_disk_usage(),
            cpu=dict(
                usage=lwp.host_cpu_percent(),
                model=host_cpu_infos['name'],
                cores=host_cpu_infos['cores']
            ),
            memory=lwp.host_memory_usage(),
            kernel=lwp.host_kernel_verion())}


host_reboot_parser = api.parser()
host_reboot_parser.add_argument('message', type=str, location='json')


class HostReboot(Resource):
    decorators = [jwt_required()]

    @user_has('host_reboot')
    @api.expect(host_reboot_fields_post)
    def post(self):
        """
        Reboot host
        """
        args = host_reboot_parser.parse_args()

        if not args.message:
            message = 'Reboot from RESTful API'
        else:
            message = args.message

        msg = '*** LXC Web Panel *** \
                \n%s' % message
        try:
            # DEBUG
            subprocess.check_call('echo \'%s\' | wall' % msg, shell=True)

            # subprocess.check_call('/sbin/shutdown -r now \'%s\'' % msg, shell=True)
            return dict(status='success',
                        message=message)
        except:
            return dict(status='error'), 500
