#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import Resource, reqparse
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
        return User.query.all()

    @user_has('users_create')
    @api.expect(users_fields_post)
    @api.marshal_with(users_fields, envelope='data')
    def post(self):
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
        user = User.query.get(id)

        if not user:
            return {'errors': "User not found"}, 404

        return user

    @user_has('users_update')
    @api.expect(users_fields_put)
    @api.marshal_with(users_fields, envelope='data')
    def put(self, id):
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
        return current_identity

    @user_has('me_edit')
    @api.expect(users_fields_put)
    @api.marshal_with(users_fields, envelope='data')
    def put(self):
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
        return Group.query.all()

    @user_has('groups_create')
    @api.expect(groups_fields_post)
    @api.marshal_with(groups_fields, envelope='data')
    def post(self):
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
        group = Group.query.get(id)

        if not group:
            return {'errors': "Group not found"}, 404

        return group

    @user_has('groups_update')
    @api.expect(groups_fields_put)
    @api.marshal_with(groups_fields, envelope='data')
    def put(self, id):
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
        return Ability.query.all()


abilities_parser = api.parser()
abilities_parser.add_argument('groups', type=list, location='json')


class Abilities(Resource):
    decorators = [jwt_required()]

    @user_has('abilities_infos')
    @api.marshal_with(abilities_fields, envelope='data')
    def get(self, id):
        ability = Ability.query.get(id)

        if not ability:
            return {'errors': "Ability not found"}, 404

        return ability

    @user_has('abilities_update')
    @api.expect(abilities_fields_put)
    @api.marshal_with(abilities_fields, envelope='data')
    def put(self, id):
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
class LxcTemplatesList(Resource):
    decorators = [jwt_required()]

    @user_has('lxc_infos')
    def get(self):
        return {'templates': lwp.get_templates_list()}, 200


class LxcTemplatesInfos(Resource):
    decorators = [jwt_required()]

    @user_has('lxc_infos')
    def get(self, template):
        return lwp.get_template_options(template), 200


##################
# Containers API #
##################
class ContainersList(Resource):
    decorators = [jwt_required()]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(ContainersList, self).__init__()

    @user_has('ct_infos')
    def get(self):
        containers = []

        for c in lxc.list_containers():
            if c in current_identity.containers:
                containers.append(lwp.ct_infos(c))

        sorted_dict = sorted(containers, key=lambda k: k['sorted_dict'])
        for ct_dict in sorted_dict:
            del ct_dict['sorted_dict']

        return {'containers': sorted_dict}  # Sorted like the frontend

    @user_has('ct_create')
    def post(self):
        self.reqparse.add_argument('name', type=str, required=True,
                                   location='json')
        self.reqparse.add_argument('template', type=str, required=True,
                                   location='json')
        self.reqparse.add_argument('args', type=dict, location='json')
        args = self.reqparse.parse_args()

        c = lxc.Container(args.name)

        # Add the container in the user containers list
        user = User.query.get(current_identity.id)
        user.containers.append(args.name)

        if not c.defined:
            if not c.create(template=args.template, args=args.args):
                return {'errors': 'Can\'t create container %s!'
                                 % args.name}, 500
            db.session.commit()
            return Containers.get(self, args.name), 201

        return {'errors': 'Container %s already exists!' % args.name}, 409


class Containers(Resource):
    decorators = [jwt_required()]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Containers, self).__init__()

    @user_has('ct_infos')
    def get(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_identity.containers:
            return lwp.ct_infos(container)

        return {'errors': 'Container %s doesn\'t exists!' % container}

    @user_has('ct_update')
    def put(self, container):
        c = lxc.Container(container)

        self.reqparse.add_argument('name', type=str, location='json')
        self.reqparse.add_argument('hostname', type=str, location='json')
        # self.reqparse.add_argument('interfaces', type=list, location='json')
        # self.reqparse.add_argument('ips', type=list, location='json')
        self.reqparse.add_argument('memory_limit', type=int, location='json')
        self.reqparse.add_argument('swap_limit', type=int, location='json')
        self.reqparse.add_argument('start_auto', type=int, location='json')
        self.reqparse.add_argument('start_delay', type=int, location='json')
        self.reqparse.add_argument('start_order', type=int, location='json')
        self.reqparse.add_argument('groups', type=list, location='json')
        self.reqparse.add_argument('cpu_shares', type=int, location='json')
        self.reqparse.add_argument('cpus', type=str, location='json')

        args = self.reqparse.parse_args()

        if c.defined and container in current_identity.containers:
            if args.name and args.name != c.name:
                if not c.rename(args.name):
                    return {'errors': 'Can\'t rename container %s to %s!'
                                     % (container, args.name)}

                container = args.name
                c = lxc.Container(container)

            if args.hostname:
                if not c.set_config_item("lxc.utsname", args.hostname):
                    return {'errors': 'Can\'t update hostname for %s to %s!'
                            % (container, args.hostname)}, 500

            if args.memory_limit:
                # Convert MB to B
                if not c.set_config_item("lxc.cgroup.memory.limit_in_bytes", str(args.memory_limit * 1048576)):
                    return {'errors': 'Can\'t update memory limit for %s to %s!'
                            % (container, args.memory_limit)}, 500

            if args.swap_limit:
                # Convert MB to B
                if not c.set_config_item("lxc.cgroup.memory.memsw.limit_in_bytes", str(args.swap_limit * 1048576)):
                    return {'errors': 'Can\'t update swap limit for %s to %s!'
                            % (container, args.memory_limit)}, 500

            if args.start_auto:
                if not c.set_config_item("lxc.start.auto", args.start_auto):
                    return {'errors': 'Can\'t set start auto for %s to %s!'
                            % (container, args.start_auto)}, 500

            if args.start_delay:
                if not c.set_config_item("lxc.start.delay", args.start_delay):
                    return {'errors': 'Can\'t set start delay for %s to %s!'
                            % (container, args.start_delay)}, 500

            if args.start_order:
                if not c.set_config_item("lxc.start.order", args.start_order):
                    return {'errors': 'Can\'t set start order for %s to %s!'
                            % (container, args.start_order)}, 500

            if args.groups:
                if not c.set_config_item("lxc.group", args.groups):
                    return {'errors': 'Can\'t set group for %s to %s!'
                            % (container, args.groups)}, 500

            if args.cpu_shares:
                if not c.set_config_item("lxc.cpu.shares", args.cpu_shares):
                    return {'errors': 'Can\'t set cpu shares for %s to %s!'
                            % (container, args.cpu_shares)}, 500

            if args.cpus:
                if not c.set_config_item("lxc.cpuset.cpus", args.cpus):
                    return {'errors': 'Can\'t set start auto for %s to %s!'
                            % (container, args.cpus)}, 500

            if args.name or args.hostname or args.memory_limit:
                c.save_config()

            return Containers.get(self, container)

        return {'errors': 'Container %s doesn\'t exists!' % container}, 404

    @user_has('ct_delete')
    def delete(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_identity.containers:
            if c.running:
                if not c.stop():
                    return {'errors': 'Can\'t stop container %s!'
                                     % container}, 409
            if not c.destroy():
                return {'errors': 'Can\'t destroy container %s!'
                                 % container}, 409
            return {'success': 'Container %s destroyed successfully!' % container}, 200

        return {'errors': 'Container %s doesn\'t exists!' % container}, 404


class ContainersStart(Resource):
    decorators = [jwt_required()]

    @user_has('ct_start')
    def post(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_identity.containers:
            c.start()
            c.wait('RUNNING', 3)
            return Containers.get(self, container)

        return {'errors': 'Container %s doesn\'t exists!' % container}, 404


class ContainersFreeze(Resource):
    decorators = [jwt_required()]

    @user_has('ct_freeze')
    def post(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_identity.containers:
            c.freeze()
            c.wait('FROZEN', 3)
            return Containers.get(self, container)

        return {'errors': 'Container %s doesn\'t exists!' % container}, 404


class ContainersUnfreeze(Resource):
    decorators = [jwt_required()]

    @user_has('ct_unfreeze')
    def post(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_identity.containers:
            c.unfreeze()
            c.wait('RUNNING', 3)
            return Containers.get(self, container)

        return {'errors': 'Container %s doesn\'t exists!' % container}, 404


class ContainersStop(Resource):
    decorators = [jwt_required()]

    @user_has('ct_stop')
    def post(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_identity.containers:
            c.stop()
            c.wait('STOPPED', 3)
            return Containers.get(self, container)

        return {'errors': 'Container %s doesn\'t exists!' % container}, 404


class ContainersShutdown(Resource):
    decorators = [jwt_required()]

    @user_has('ct_stop')
    def post(self, container):
        c = lxc.Container(container)

        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('timeout', type=int, default=10)
        args = self.reqparse.parse_args()

        if c.defined and container in current_identity.containers:
            c.shutdown(args.timeout)
            c.wait('STOPPED', 3)
            return Containers.get(self, container)

        return {'errors': 'Container %s doesn\'t exists!' % container}, 404


class ContainersRestart(Resource):
    decorators = [jwt_required()]

    @user_has('ct_restart')
    def post(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_identity.containers:
            ContainersStop.post(self, container)
            ContainersStart.post(self, container)
            return Containers.get(self, container)

        return {'errors': 'Container %s doesn\'t exists!' % container}, 404


class LxcCheckConfig(Resource):
    decorators = [jwt_required()]

    @user_has('lxc_infos')
    def get(self):
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

        config_dict['Namespaces'] = is_enabled('CONFIG_NAMESPACES', True)
        config_dict['Utsname namespace'] = is_enabled('CONFIG_UTS_NS')
        config_dict['Ipc namespace'] = is_enabled('CONFIG_IPC_NS', True)
        config_dict['Pid namespace'] = is_enabled('CONFIG_PID_NS', True)
        config_dict['User namespace'] = is_enabled('CONFIG_USER_NS')
        config_dict['Network namespace'] = is_enabled('CONFIG_NET_NS')
        config_dict[
            'Multiple /dev/pts instances'] = is_enabled('CONFIG_DEVPTS_MULTIPLE_INSTANCES')
        config_dict['Cgroup'] = is_enabled('CONFIG_CGROUPS', True)
        config_dict['Cgroup namespace'] = is_enabled('CONFIG_CGROUP_NS', True)
        config_dict['Cgroup device'] = is_enabled('CONFIG_CGROUP_DEVICE')
        config_dict['Cgroup sched'] = is_enabled('CONFIG_CGROUP_SCHED')
        config_dict['Cgroup cpu account'] = is_enabled('CONFIG_CGROUP_CPUACCT')

        if kver_major >= 3 and kver_minor >= 6:
            config_dict['Cgroup memory controller'] = is_enabled(
                'CONFIG_MEMCG')
        else:
            config_dict['Cgroup memory controller'] = is_enabled(
                'CONFIG_CGROUP_MEM_RES_CTLR')

        if is_set('CONFIG_SMP'):
            config_dict['Cgroup cpuset'] = is_enabled('CONFIG_CPUSETS')

        config_dict['Veth pair device'] = is_enabled('CONFIG_VETH')
        config_dict['Macvlan'] = is_enabled('CONFIG_MACVLAN')
        config_dict['Vlan'] = is_enabled('CONFIG_VLAN_8021Q')

        if kver_major == 2 and kver_minor < 33:
            config_dict['File capabilities'] = is_enabled(
                'CONFIG_SECURITY_FILE_CAPABILITIES')
        if (kver_major == 2 and kver_minor > 32) or kver_major > 2:
            config_dict['File capabilities'] = 'enabled'

        return config_dict


class HostStats(Resource):
    decorators = [jwt_required()]

    @user_has('host_stats')
    def get(self):
        os = platform.dist()
        os_str = ' '.join(os)
        host_cpu_infos = lwp.host_cpu_infos()

        return dict(uptime=lwp.host_uptime(),
                    hostname=socket.gethostname(),
                    dist=os_str,
                    disk_usage=lwp.host_disk_usage(),
                    cpu=dict(
            usage=lwp.host_cpu_percent(),
            model=host_cpu_infos['name'],
            cores=host_cpu_infos['cores']
        ),
            memory=lwp.host_memory_usage(),
            kernel=lwp.host_kernel_verion())


class HostReboot(Resource):
    decorators = [jwt_required()]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(HostReboot, self).__init__()

    @user_has('host_reboot')
    def post(self):
        self.reqparse.add_argument('message', type=str, location='json')
        args = self.reqparse.parse_args()

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
            return dict(status='error')
