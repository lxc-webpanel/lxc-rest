#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import request
from flask_restplus import Resource, reqparse
from flask_restplus.reqparse import Argument
from flask_jwt_extended import jwt_required, create_access_token, \
    jwt_refresh_token_required
from app import db, api
from .models import *
from .decorators import *
from .fields.auth import *
from .fields.users import *
from .fields.groups import *
from .fields.abilities import *
from .fields.containers import *
from .fields.hosts import *
import lwp
import lxc
import os.path
import platform
import re
import gzip
import socket
import subprocess
import psutil


class Auth(Resource):

    @api.marshal_with(auth_fields_get)
    @api.expect(auth_fields_post, validate=True)
    def post(self):
        """
        Get Json Web Token
        """
        username = request.json.get('username', None)
        password = request.json.get('password', None)

        user = User.query.filter_by(username=username).first()

        if not user or not user.verify_password(password):
            api.abort(code=401, message='Incorrect user or password')

        ret = {'access_token': create_access_token(identity=user)}
        return ret


class AuthRefresh(Resource):
    decorators = [jwt_required]

    @api.marshal_with(auth_fields_get)
    def post(self):
        """
        Get new token with valid token
        """
        current_identity = import_user()
        ret = {
            'access_token': create_access_token(identity=current_identity)
        }
        return ret


class AuthCheck(Resource):
    decorators = [jwt_required]

    @api.doc(responses={
        200: 'Token OK',
        401: 'Token invalid or expired',
        422: 'Signature verification failed'
    })
    def get(self):
        """
        Check token
        """
        return {}, 200


class UsersList(Resource):
    decorators = [jwt_required]

    @user_has('users_infos_all')
    @api.marshal_with(users_fields_get_many)
    def get(self):
        """
        Get users list
        """
        users = User.query.all()
        users_list = []

        for user in users:
            users_list.append(user.__jsonapi__())

        return {'data': users_list}

    @user_has('users_create')
    @api.expect(users_fields_post, validate=True)
    @api.marshal_with(users_fields_get)
    def post(self):
        """
        Create user
        """
        current_identity = import_user()
        data = request.get_json()['data']
        if User.query.filter_by(username=data['attributes']['username']).first():
            api.abort(code=409, message='User already exists')

        user = User()

        user.username = data['attributes']['username']
        user.name = data['attributes']['name']
        user.hash_password(data['attributes']['password'])

        if 'admin' in data['attributes'] and current_identity.admin:
            user.admin = data['attributes']['admin']
        if 'email' in data['attributes']:
            user.email = data['attributes']['email']

        try:
            user.groups = list(id['id'] for id in data[
                               'relationships']['groups']['data'])
        except KeyError:
            pass

        try:
            user.containers = list(id['id'] for id in data[
                                   'relationships']['containers']['data'])
        except KeyError:
            pass

        db.session.add(user)
        db.session.commit()

        return {'data': user.__jsonapi__()}, 201


class Users(Resource):
    decorators = [jwt_required]

    @user_has('users_infos')
    @api.marshal_with(users_fields_get)
    def get(self, id):
        """
        Get user
        """
        user = User.query.get(id)

        if not user:
            api.abort(code=404, message='User not found')

        return {'data': user.__jsonapi__()}

    @user_has('users_update')
    @api.expect(users_fields_put, validate=True)
    @api.marshal_with(users_fields_get)
    def put(self, id):
        """
        Update user
        """
        current_identity = import_user()
        user = User.query.get(id)

        if not user:
            api.abort(code=404, message='User not found')

        data = request.get_json()['data']

        if 'name' in data['attributes']:
            user.name = data['attributes']['name']
        if 'admin' in data['attributes'] and current_identity.admin:
            user.admin = data['attributes']['admin']
        if 'email' in data['attributes']:
            user.email = data['attributes']['email']
        if 'password' in data['attributes']:
            user.hash_password(data['attributes']['password'])

        try:
            user.groups = list(id['id'] for id in data[
                               'relationships']['groups']['data'])
        except KeyError:
            pass

        try:
            user.containers = list(id['id'] for id in data[
                                   'relationships']['containers']['data'])
        except KeyError:
            pass

        if len(data) > 0:
            db.session.commit()

        return {'data': user.__jsonapi__()}

    @user_has('users_delete')
    def delete(self, id):
        """
        Delete user
        """
        user = User.query.get(id)

        if not user:
            api.abort(code=404, message='User not found')

        db.session.delete(user)
        db.session.commit()

        return {}, 204


class Me(Resource):
    decorators = [jwt_required]

    @api.marshal_with(users_fields_get)
    def get(self):
        """
        Get me
        """
        current_identity = import_user()
        return {'data': current_identity.__jsonapi__()}

    @user_has('me_edit')
    @api.expect(users_fields_put, validate=True)
    @api.marshal_with(users_fields_get)
    def put(self):
        """
        Update me
        """
        current_identity = import_user()
        user = User.query.get(current_identity.id)

        data = request.get_json()['data']

        if 'name' in data['attributes']:
            user.name = data['attributes']['name']
        if 'admin' in data['attributes'] and current_identity.admin:
            user.admin = data['attributes']['admin']
        if 'email' in data['attributes']:
            user.email = data['attributes']['email']
        if 'password' in data['attributes']:
            user.hash_password(data['attributes']['password'])

        try:
            user.groups = list(id['id'] for id in data[
                               'relationships']['groups']['data'])
        except KeyError:
            pass

        try:
            user.containers = list(id['id'] for id in data[
                                   'relationships']['containers']['data'])
        except KeyError:
            pass

        if len(data) > 0:
            db.session.commit()

        return {'data': user.__jsonapi__()}

    @user_has('me_edit')
    def delete(self):
        """
        Delete me (stupid)
        """
        current_identity = import_user()
        user = User.query.get(current_identity.id)

        db.session.delete(user)
        db.session.commit()

        return {}, 204


class GroupsList(Resource):
    decorators = [jwt_required]

    @user_has('groups_infos_all')
    @api.marshal_with(groups_fields_get_many)
    def get(self):
        """
        Get groups list
        """
        groups = Group.query.all()
        groups_list = []

        for group in groups:
            groups_list.append(group.__jsonapi__())

        return {'data': groups_list}

    @user_has('groups_create')
    @api.expect(groups_fields_post, validate=True)
    @api.marshal_with(groups_fields_get)
    def post(self):
        """
        Create group
        """
        data = request.get_json()['data']

        group = Group(name=data['attributes']['name'])

        try:
            group.abilities = list(id['id'] for id in data[
                                   'relationships']['abilities']['data'])
        except KeyError:
            pass

        try:
            group.users = list(id['id'] for id in data[
                'relationships']['users']['data'])
        except KeyError:
            pass

        db.session.add(group)
        db.session.commit()

        return {'data': group.__jsonapi__()}, 201


class Groups(Resource):
    decorators = [jwt_required]

    @user_has('groups_infos')
    @api.marshal_with(groups_fields_get)
    def get(self, id):
        """
        Get group
        """
        group = Group.query.get(id)

        if not group:
            api.abort(code=404, message='Group not found')

        return {'data': group.__jsonapi__()}

    @user_has('groups_update')
    @api.expect(groups_fields_put, validate=True)
    @api.marshal_with(groups_fields_get)
    def put(self, id):
        """
        Update group
        """
        group = Group.query.get(id)

        if not group:
            api.abort(code=404, message='Group not found')

        data = request.get_json()['data']

        if 'name' in data['attributes']:
            group.name = data['attributes']['name']

        try:
            group.abilities = list(id['id'] for id in data[
                                   'relationships']['abilities']['data'])
        except KeyError:
            pass

        try:
            group.users = list(id['id'] for id in data[
                'relationships']['users']['data'])
        except KeyError:
            pass

        if len(data) > 0:
            db.session.commit()

        return {'data': group.__jsonapi__()}

    @user_has('groups_delete')
    def delete(self, id):
        """
        Delete group
        """
        group = Group.query.get(id)

        if not group:
            api.abort(code=404, message='Group not found')

        db.session.delete(group)
        db.session.commit()

        return {}, 204


class AbilitiesList(Resource):
    decorators = [jwt_required]

    @user_has('abilities_infos_all')
    @api.marshal_with(abilities_fields_get_many)
    def get(self):
        """
        Get abilities list
        """
        abilities = Ability.query.all()
        abilities_list = []

        for ability in abilities:
            abilities_list.append(ability.__jsonapi__())

        return {'data': abilities_list}


class Abilities(Resource):
    decorators = [jwt_required]

    @user_has('abilities_infos')
    @api.marshal_with(abilities_fields_get)
    def get(self, id):
        """
        Get ability
        """
        ability = Ability.query.get(id)

        if not ability:
            api.abort(code=404, message='Ability not found')

        return {'data': ability.__jsonapi__()}

    @user_has('abilities_update')
    @api.expect(abilities_fields_put, validate=True)
    @api.marshal_with(abilities_fields_get)
    def put(self, id):
        """
        Update ability
        """
        ability = Ability.query.get(id)

        data = request.get_json()['data']

        try:
            if len(data['relationships']['groups']['data']) >= 0:
                ability.groups = list(id['id'] for id in data[
                                      'relationships']['groups']['data'])
                db.session.commit()
        except KeyError:
            pass

        return {'data': ability.__jsonapi__()}


##################
# Containers API #
##################
class ContainersList(Resource):
    decorators = [jwt_required]

    @user_has('ct_infos')
    @api.marshal_with(containers_fields_get_many)
    def get(self):
        """
        Get containers list
        """
        current_identity = import_user()
        containers = []

        for c in lxc.list_containers():
            container = Container.query.filter_by(name=c).first()
            if container.id in current_identity.containers or current_identity.admin:
                infos = lwp.ct_infos(c)
                container_json = container.__jsonapi__()
                container_json['attributes'] = infos
                containers.append(container_json)

        return {'data': containers}

    @user_has('ct_create')
    @api.expect(containers_fields_post, validate=True)
    @api.marshal_with(containers_fields_get)
    @api.doc(responses={
        201: 'Container created',
        409: 'Container already exists',
        500: 'Can\'t create container'
    })
    def post(self):
        """
        Create container
        """
        current_identity = import_user()
        data = request.get_json()['data']

        if 'name' in data['attributes']:
            c = lxc.Container(data['attributes']['name'])
            if not c.defined:
                try:
                    if not isinstance(data['attributes']['template']['args'], str):
                        data['attributes']['template']['args'] = ''
                except KeyError:
                    data['attributes']['template']['args'] = ''
                if not c.create(
                    template=data['attributes']['template']['name'],
                    flags=lxc.LXC_CREATE_QUIET,
                    args=data['attributes']['template']['args'],
                    bdevtype=None
                ):
                    api.abort(code=500, message='Can\'t create container')

                # Add container to database
                container = Container(name=data['attributes']['name'])
                db.session.add(container)
                db.session.commit()
                # Get container ID
                container = Container.query.filter_by(
                    name=data['attributes']['name']).first()
                # Add container to allowed user's containers
                user = User.query.get(current_identity.id)
                user.containers.append(container.id)
                db.session.commit()

                return Containers.put(self, container.id, d=data), 201
            api.abort(code=409, message='Container already exists')


class Containers(Resource):
    decorators = [jwt_required]

    @user_has('ct_infos')
    @api.marshal_with(containers_fields_get)
    def get(self, id):
        """
        Get container
        """
        current_identity = import_user()
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and (id in current_identity.containers or current_identity.admin):
            infos = lwp.ct_infos(container.name)
            container_json = container.__jsonapi__()
            container_json['attributes'] = infos

            return {'data': container_json}
        api.abort(code=404, message='Container doesn\'t exists')

    @user_has('ct_update')
    @api.expect(containers_fields_put, validate=True)
    @api.marshal_with(containers_fields_get)
    def put(self, id, d=None):
        """
        Update container
        """
        def set_config(container, config_item, config_value):
            if container.set_config_item(config_item, config_value):
                container.save_config()

                # python-lxc workaround (issue #1415 on lxc/lxc)
                f = open(container.config_file_name, "r")
                lines = f.readlines()
                f.close()
                f = open(container.config_file_name, "w")
                for line in lines:
                    if not line.endswith(' = \n'):
                        f.write(line)
                f.close()
            else:
                api.abort(
                    code=500, message='Error while setting container\'s parameter')

        # Get data from ContainersList.post()
        # or
        # from Containers.put()
        if d:
            data = d
        else:
            data = request.get_json()['data']

        current_identity = import_user()
        container = Container.query.get(id)

        c = lxc.Container(container.name)

        if c.defined and (id in current_identity.containers or current_identity.admin):
            if 'name' in data['attributes']:
                if data['attributes']['name'] != c.name:
                    if c.rename(data['attributes']['name']):
                        c = lxc.Container(data['attributes']['name'])
                    else:
                        api.abort(
                            code=500, message='Error while instantiate container')

            if 'lxc' in data['attributes']:
                if 'aa_allow_incomplete' in data['attributes']['lxc']:
                    set_config(c, 'lxc.aa_allow_incomplete', data['attributes'][
                               'lxc']['aa_allow_incomplete'])
                if 'aa_profile' in data['attributes']['lxc']:
                    set_config(c, 'lxc.aa_profile', data[
                               'attributes']['lxc']['aa_profile'])
                if 'arch' in data['attributes']['lxc']:
                    set_config(c, 'lxc.arch', data[
                               'attributes']['lxc']['arch'])
                if 'autodev' in data['attributes']['lxc']:
                    set_config(c, 'lxc.autodev', data[
                               'attributes']['lxc']['autodev'])
                if 'cap' in data['attributes']['lxc']:
                    if 'drop' in data['attributes']['lxc']['cap']:
                        set_config(c, 'lxc.cap.drop', data['attributes'][
                                   'lxc']['cap']['drop'])
                    if 'keep' in data['attributes']['lxc']['cap']:
                        set_config(c, 'lxc.cap.keep', data['attributes'][
                                   'lxc']['cap']['keep'])
                if 'cgroup' in data['attributes']['lxc']:
                    if 'memory' in data['attributes']['lxc']['cgroup']:
                        if 'limit_in_bytes' in data['attributes']['lxc']['cgroup']['memory']:
                            set_config(c, 'lxc.cgroup.memory.limit_in_bytes', data['attributes'][
                                       'lxc']['cgroup']['memory']['limit_in_bytes'])
                        if 'memsw' in data['attributes']['lxc']['cgroup']['memory']:
                            if 'limit_in_bytes' in data['attributes']['lxc']['cgroup']['memory']['memsw']:
                                set_config(c, 'lxc.cgroup.memory.memsw.limit_in_bytes', data['attributes'][
                                           'lxc']['cgroup']['memory']['memsw']['limit_in_bytes'])
                    if 'cpu' in data['attributes']['lxc']['cgroup']:
                        if 'shares' in data['attributes']['lxc']['cgroup']['cpu']:
                            set_config(c, 'lxc.cgroup.cpu.shares', data['attributes'][
                                       'lxc']['cgroup']['cpu']['shares'])
                    if 'cpuset' in data['attributes']['lxc']['cgroup']:
                        if 'cpus' in data['attributes']['lxc']['cgroup']['cpuset']:
                            set_config(c, 'lxc.cgroup.cpuset.cpus', data['attributes'][
                                       'lxc']['cgroup']['cpuset']['cpus'])
                if 'console' in data['attributes']['lxc']:
                    if '_' in data['attributes']['lxc']['console']:
                        set_config(c, 'lxc.console', data['attributes'][
                                   'lxc']['console']['_'])
                    if 'logfile' in data['attributes']['lxc']['console']:
                        set_config(c, 'lxc.console.logfile', data['attributes'][
                                   'lxc']['console']['logfile'])
                if 'devttydir' in data['attributes']['lxc']:
                    set_config(c, 'lxc.devttydir', data[
                               'attributes']['lxc']['devttydir'])
                if 'environment' in data['attributes']['lxc']:
                    set_config(c, 'lxc.environment', data['attributes'][
                               'lxc']['environment'])
                if 'ephemeral' in data['attributes']['lxc']:
                    set_config(c, 'lxc.ephemeral', data[
                               'attributes']['lxc']['ephemeral'])
                if 'group' in data['attributes']['lxc']:
                    set_config(c, 'lxc.group', data[
                               'attributes']['lxc']['group'])
                if 'haltsignal' in data['attributes']['lxc']:
                    set_config(c, 'lxc.haltsignal', data[
                               'attributes']['lxc']['haltsignal'])
                if 'hook' in data['attributes']['lxc']:
                    if 'autodev' in data['attributes']['lxc']['hook']:
                        set_config(c, 'lxc.hook.autodev', data['attributes'][
                                   'lxc']['hook']['autodev'])
                    if 'clone' in data['attributes']['lxc']['hook']:
                        set_config(c, 'lxc.hook.clone', data['attributes'][
                                   'lxc']['hook']['clone'])
                    if 'destroy' in data['attributes']['lxc']['hook']:
                        set_config(c, 'lxc.hook.destroy', data['attributes'][
                                   'lxc']['hook']['destroy'])
                    if 'mount' in data['attributes']['lxc']['hook']:
                        set_config(c, 'lxc.hook.mount', data['attributes'][
                                   'lxc']['hook']['mount'])
                    if 'post-stop' in data['attributes']['lxc']['hook']:
                        set_config(c, 'lxc.hook.post-stop',
                                   data['attributes']['lxc']['hook']['post-stop'])
                    if 'pre-mount' in data['attributes']['lxc']['hook']:
                        set_config(c, 'lxc.hook.pre-mount',
                                   data['attributes']['lxc']['hook']['pre-mount'])
                    if 'pre-start' in data['attributes']['lxc']['hook']:
                        set_config(c, 'lxc.hook.pre-start',
                                   data['attributes']['lxc']['hook']['pre-start'])
                    if 'start' in data['attributes']['lxc']['hook']:
                        set_config(c, 'lxc.hook.start', data['attributes'][
                                   'lxc']['hook']['start'])
                    if 'stop' in data['attributes']['lxc']['hook']:
                        set_config(c, 'lxc.hook.stop', data['attributes'][
                                   'lxc']['hook']['stop'])
                if 'id_map' in data['attributes']['lxc']:
                    set_config(c, 'lxc.id_map', data[
                               'attributes']['lxc']['id_map'])
                if 'include' in data['attributes']['lxc']:
                    set_config(c, 'lxc.include', data[
                               'attributes']['lxc']['include'])
                if 'init_cmd' in data['attributes']['lxc']:
                    set_config(c, 'lxc.init_cmd', data[
                               'attributes']['lxc']['init_cmd'])
                if 'init_gid' in data['attributes']['lxc']:
                    set_config(c, 'lxc.init_gid', data[
                               'attributes']['lxc']['init_gid'])
                if 'init_uid' in data['attributes']['lxc']:
                    set_config(c, 'lxc.init_uid', data[
                               'attributes']['lxc']['init_uid'])
                if 'kmsg' in data['attributes']['lxc']:
                    set_config(c, 'lxc.kmsg', data[
                               'attributes']['lxc']['kmsg'])
                if 'logfile' in data['attributes']['lxc']:
                    set_config(c, 'lxc.logfile', data[
                               'attributes']['lxc']['logfile'])
                if 'loglevel' in data['attributes']['lxc']:
                    set_config(c, 'lxc.loglevel', data[
                               'attributes']['lxc']['loglevel'])
                if 'monitor' in data['attributes']['lxc']:
                    if 'unshare' in data['attributes']['lxc']['monitor']:
                        set_config(c, 'lxc.monitor.unshare', data['attributes'][
                                   'lxc']['monitor']['unshare'])
                if 'mount' in data['attributes']['lxc']:
                    if '_' in data['attributes']['lxc']['mount']:
                        set_config(c, 'lxc.mount', data[
                                   'attributes']['lxc']['mount']['_'])
                    if 'auto' in data['attributes']['lxc']['mount']:
                        set_config(c, 'lxc.mount.auto', data['attributes'][
                                   'lxc']['mount']['auto'])
                    if 'entry' in data['attributes']['lxc']['mount']:
                        set_config(c, 'lxc.mount.entry', data['attributes'][
                                   'lxc']['mount']['entry'])
                if 'network' in data['attributes']['lxc']:
                    for i in range(len(data['attributes']['lxc']['network'])):
                        if 'type' in data['attributes']['lxc']['network'][i]:
                            set_config(c, 'lxc.network.%s.type' %
                                       i, data['attributes']['lxc']['network'][i]['type'])
                        if 'veth' in data['attributes']['lxc']['network'][i]:
                            if 'pair' in data['attributes']['lxc']['network'][i]['veth']:
                                set_config(c, 'lxc.network.%s.veth.pair' %
                                           i, data['attributes']['lxc']['network'][i]['veth']['pair'])
                        if 'vlan' in data['attributes']['lxc']['network'][i]:
                            if 'id' in data['attributes']['lxc']['network'][i]['vlan']:
                                set_config(c, 'lxc.network.%s.vlan.id' %
                                           i, data['attributes']['lxc']['network'][i]['vlan']['id'])
                        if 'macvlan' in data['attributes']['lxc']['network'][i]:
                            if 'mode' in data['attributes']['lxc']['network'][i]['macvlan']:
                                set_config(c, 'lxc.network.%s.macvlan.mode' % i, data['attributes'][
                                           'lxc']['network'][i]['macvlan']['mode'])
                        if 'flags' in data['attributes']['lxc']['network'][i]:
                            set_config(c, 'lxc.network.%s.flags' %
                                       i, data['attributes']['lxc']['network'][i]['flags'])
                        if 'link' in data['attributes']['lxc']['network'][i]:
                            set_config(c, 'lxc.network.%s.link' %
                                       i, data['attributes']['lxc']['network'][i]['link'])
                        if 'mtu' in data['attributes']['lxc']['network'][i]:
                            set_config(c, 'lxc.network.%s.mtu' %
                                       i, data['attributes']['lxc']['network'][i]['mtu'])
                        if 'name' in data['attributes']['lxc']['network'][i]:
                            set_config(c, 'lxc.network.%s.name' %
                                       i, data['attributes']['lxc']['network'][i]['name'])
                        if 'hwaddr' in data['attributes']['lxc']['network'][i]:
                            set_config(c, 'lxc.network.%s.hwaddr' %
                                       i, data['attributes']['lxc']['network'][i]['hwaddr'])
                        if 'ipv4' in data['attributes']['lxc']['network'][i]:
                            if '_' in data['attributes']['lxc']['network'][i]['ipv4']:
                                set_config(c, 'lxc.network.%s.ipv4' %
                                           i, data['attributes']['lxc']['network'][i]['ipv4']['_'])

                            if 'gateway' in data['attributes']['lxc']['network'][i]['ipv4']:
                                set_config(c, 'lxc.network.%s.ipv4.gateway' % i, data['attributes'][
                                           'lxc']['network'][i]['ipv4']['gateway'])
                        if 'ipv6' in data['attributes']['lxc']['network'][i]:
                            if '_' in data['attributes']['lxc']['network'][i]['ipv6']:
                                set_config(c, 'lxc.network.%s.ipv6' %
                                           i, data['attributes']['lxc']['network'][i]['ipv6']['_'])
                            if 'gateway' in data['attributes']['lxc']['network'][i]['ipv6']:
                                set_config(c, 'lxc.network.%s.ipv6.gateway' % i, data['attributes'][
                                           'lxc']['network'][i]['ipv6']['gateway'])
                        if 'script' in data['attributes']['lxc']['network'][i]:
                            if 'up' in data['attributes']['lxc']['network'][i]['script']:
                                set_config(c, 'lxc.network.%s.script.up' %
                                           i, data['attributes']['lxc']['network'][i]['script']['up'])
                            if 'down' in data['attributes']['lxc']['network'][i]['script']:
                                set_config(c, 'lxc.network.%s.script.down' % i, data['attributes'][
                                           'lxc']['network'][i]['script']['down'])
                if 'no_new_privs' in data['attributes']['lxc']:
                    set_config(c, 'lxc.no_new_privs', data['attributes'][
                               'lxc']['no_new_privs'])
                if 'pts' in data['attributes']['lxc']:
                    set_config(c, 'lxc.pts', data['attributes']['lxc']['pts'])
                if 'rebootsignal' in data['attributes']['lxc']:
                    set_config(c, 'lxc.rebootsignal', data['attributes'][
                               'lxc']['rebootsignal'])
                if 'rootfs' in data['attributes']['lxc']:
                    if '_' in data['attributes']['lxc']['rootfs']:
                        set_config(c, 'lxc.rootfs', data[
                                   'attributes']['lxc']['rootfs']['_'])
                    if 'mount' in data['attributes']['lxc']['rootfs']:
                        set_config(c, 'lxc.rootfs.mount', data['attributes'][
                                   'lxc']['rootfs']['mount'])
                    if 'options' in data['attributes']['lxc']['rootfs']:
                        set_config(c, 'lxc.rootfs.options', data['attributes'][
                                   'lxc']['rootfs']['options'])
                    if 'backend' in data['attributes']['lxc']['rootfs']:
                        set_config(c, 'lxc.rootfs.backend', data['attributes'][
                                   'lxc']['rootfs']['backend'])
                if 'se_context' in data['attributes']['lxc']:
                    set_config(c, 'lxc.se_context', data[
                               'attributes']['lxc']['se_context'])
                if 'seccomp' in data['attributes']['lxc']:
                    set_config(c, 'lxc.seccomp', data[
                               'attributes']['lxc']['seccomp'])
                if 'start' in data['attributes']['lxc']:
                    if 'auto' in data['attributes']['lxc']['start']:
                        set_config(c, 'lxc.start.auto', data['attributes'][
                                   'lxc']['start']['auto'])
                    if 'delay' in data['attributes']['lxc']['start']:
                        set_config(c, 'lxc.start.delay', data['attributes'][
                                   'lxc']['start']['delay'])
                    if 'order' in data['attributes']['lxc']['start']:
                        set_config(c, 'lxc.start.order', data['attributes'][
                                   'lxc']['start']['order'])
                if 'stopsignal' in data['attributes']['lxc']:
                    set_config(c, 'lxc.stopsignal', data[
                               'attributes']['lxc']['stopsignal'])
                if 'syslog' in data['attributes']['lxc']:
                    set_config(c, 'lxc.syslog', data[
                               'attributes']['lxc']['syslog'])
                if 'tty' in data['attributes']['lxc']:
                    set_config(c, 'lxc.tty', data['attributes']['lxc']['tty'])
                if 'utsname' in data['attributes']['lxc']:
                    set_config(c, 'lxc.utsname', data[
                               'attributes']['lxc']['utsname'])

            return Containers.get(self, container.id)
        api.abort(code=404, message='Container doesn\'t exists')

    @user_has('ct_delete')
    @api.doc(responses={
        204: 'Container destroyed',
        404: 'Container doesn\'t exists',
        409: 'Can\'t destroy and/or stop container',
    })
    def delete(self, id):
        """
        Destroy container
        """
        current_identity = import_user()
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and (id in current_identity.containers or current_identity.admin):
            if c.running:
                if not c.stop():
                    api.abort(
                        code=409, message='Can\'t destroy and/or stop container')
            if not c.destroy():
                api.abort(
                    code=409, message='Can\'t destroy and/or stop container')
            return {}, 204
        api.abort(code=404, message='Container doesn\'t exists')


class ContainersClone(Resource):
    decorators = [jwt_required]

    @user_has('ct_clone')
    @api.expect(containers_clone_post, validate=True)
    @api.marshal_with(containers_fields_get)
    def post(self, id):
        """
        Clone container
        """
        current_identity = import_user()
        data = request.get_json()['data']

        if 'name' in data['attributes']:
            container = Container.query.get(id)
            c = lxc.Container(container.name)

            if c.defined and (id in current_identity.containers or current_identity.admin):
                c2 = lxc.Container(data['attributes']['name'])
                if not c2.defined:
                    c2 = c.clone(data['attributes']['name'],
                                 flags=lxc.LXC_CLONE_MAYBE_SNAPSHOT)
                    if c2.defined:
                        # Add container to database
                        container = Container(name=data['attributes']['name'])
                        db.session.add(container)
                        db.session.commit()
                        # Get container ID
                        container = Container.query.filter_by(
                            name=data['attributes']['name']).first()
                        # Add container to allowed user's containers
                        user = User.query.get(current_identity.id)
                        user.containers.append(container.id)
                        db.session.commit()

                        return Containers.get(self, container.id)

            api.abort(code=404, message='Container doesn\'t exists')


class ContainersStart(Resource):
    decorators = [jwt_required]

    @user_has('ct_start')
    def post(self, id):
        """
        Start container
        """
        current_identity = import_user()
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and (id in current_identity.containers or current_identity.admin):
            c.start()
            if c.wait('RUNNING', 30):
                return {}, 204
            else:
                api.abort(code=500, message='Start timed out')

        api.abort(code=404, message='Container doesn\'t exists')


class ContainersFreeze(Resource):
    decorators = [jwt_required]

    @user_has('ct_freeze')
    def post(self, id):
        """
        Freeze container
        """
        current_identity = import_user()
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and (id in current_identity.containers or current_identity.admin):
            c.freeze()
            if c.wait('FROZEN', 30):
                return {}, 204
            else:
                api.abort(code=500, message='Freeze timed out')

        api.abort(code=404, message='Container doesn\'t exists')


class ContainersUnfreeze(Resource):
    decorators = [jwt_required]

    @user_has('ct_unfreeze')
    def post(self, id):
        """
        Unfreeze container
        """
        current_identity = import_user()
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and (id in current_identity.containers or current_identity.admin):
            c.unfreeze()
            if c.wait('RUNNING', 30):
                return {}, 204
            else:
                api.abort(code=500, message='Unfreeze timed out')

        api.abort(code=404, message='Container doesn\'t exists')


class ContainersStop(Resource):
    decorators = [jwt_required]

    @user_has('ct_stop')
    def post(self, id):
        """
        Stop container
        """
        current_identity = import_user()
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and (id in current_identity.containers or current_identity.admin):
            c.stop()
            if c.wait('STOPPED', 30):
                return {}, 204
            else:
                api.abort(code=500, message='Stop timed out')

        api.abort(code=404, message='Container doesn\'t exists')


class ContainersShutdown(Resource):
    decorators = [jwt_required]

    @user_has('ct_stop')
    def post(self, id):
        """
        Shutdown container
        """
        current_identity = import_user()
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and (id in current_identity.containers or current_identity.admin):
            c.shutdown(10)
            if c.wait('STOPPED', 30):
                return {}, 204
            else:
                api.abort(code=500, message='Shutdown timed out')

        api.abort(code=404, message='Container doesn\'t exists')


class ContainersRestart(Resource):
    decorators = [jwt_required]

    @user_has('ct_restart')
    def post(self, id):
        """
        Restart container
        """
        current_identity = import_user()
        container = Container.query.get(id)
        c = lxc.Container(container.name)

        if c.defined and (id in current_identity.containers or current_identity.admin):
            try:
                if ContainersStop.post(self, id)[1] == 204 and ContainersStart.post(self, id)[1] == 204:
                    return {}, 204
            except KeyError:
                api.abort(code=500, message='Unknown error')

        api.abort(code=404, message='Container doesn\'t exists')


class LxcCheckConfig(Resource):
    decorators = [jwt_required]

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
    decorators = [jwt_required]

    @user_has('host_stats')
    @api.marshal_with(host_stats_fields_get)
    def get(self, container=False):
        """
        Get host stats (uptime, cpu, ram, etc)
        """

        host_cpu_infos = lwp.host_cpu_infos()

        cpu_count_logical = psutil.cpu_count()
        cpu_count_physical = psutil.cpu_count(logical=False)
        cpu_percent = lwp.host_cpu_percent()

        virtual_memory = psutil.virtual_memory()
        swap_memory = psutil.swap_memory()

        disk_partitions = psutil.disk_partitions()
        disk_partitions_usage = []
        for partition in disk_partitions:
            partition_data = psutil.disk_usage(partition.mountpoint)
            disk_partitions_usage.append({
                'name': partition.mountpoint,
                'total': partition_data.total,
                'used': partition_data.used,
                'free': partition_data.free,
                'percent': partition_data.percent
            })

        net_if_addrs = psutil.net_if_addrs()

        adapters = []

        for adapter in net_if_addrs:
            adapters.append({
                'name': adapter,
                'ipv4': None,
                'ipv6': None
            })
            index = len(adapters) - 1
            for snic in net_if_addrs[adapter]:
                if snic.family.name == 'AF_INET':
                    adapters[index]['ipv4'] = snic.address
                if snic.family.name == 'AF_INET6':
                    adapters[index]['ipv6'] = snic.address

        json_output = {
            'uptime': lwp.host_uptime(),
            'hostname': socket.gethostname(),
            'distrib': ' '.join(platform.dist()),
            'disk': disk_partitions_usage,
            'cpu': {
                'usage': cpu_percent,
                'model': host_cpu_infos['name'],
                'physical': cpu_count_physical,
                'logical': cpu_count_logical
            },
            'memory': {
                'virtual': {
                    'total': virtual_memory.total,
                    'used': virtual_memory.used,
                    'free': virtual_memory.free,
                    'percent': virtual_memory.percent
                },
                'swap': {
                    'total': swap_memory.total,
                    'used': swap_memory.used,
                    'free': swap_memory.free,
                    'percent': swap_memory.percent
                }
            },
            'adapters': adapters,
            'kernel': platform.release(),
            'lxc': {
                'version': lxc.version,
                'lxcpath': lxc.get_global_config_item('lxc.lxcpath'),
                'default_config': lxc.get_global_config_item('lxc.default_config')
            }
        }

        if not container:
            output = {
                'attributes': json_output
            }
        else:
            output = json_output

        return {'data': output}

host_reboot_parser = api.parser()
host_reboot_parser.add_argument('message', type=str, location='json')


class HostReboot(Resource):
    decorators = [jwt_required]

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
            return {
                'status': 'success',
                'message': message
            }
        except:
            api.abort(code=500, message='Error during system call')
