#!/usr/bin/python3
import os.path
import platform
import re
import gzip
import socket
import subprocess
import json

import lwp
import lxc

from functools import wraps
from werkzeug.exceptions import Forbidden

from datetime import timedelta
from flask.ext.restful import Api, Resource, reqparse, fields, marshal
from flask.ext.sqlalchemy import SQLAlchemy
from flask import Flask, make_response
from flask_jwt import JWT, jwt_required, current_user
from flask_lwp_permissions.core import Permissions

#### DEV TODO
# Add same features as lwp 0.2 to GET /containers and PUT /containers/<name>
# Put https://github.com/googley/lxc-checkconfig (or https://github.com/otaku42/lxc-checkconfig/tree/workover) in /api/v1/lxc/checkconfig
# Create super user status for containers listing
# Create config file (json, yaml or ini?)
# Create /templates (based on lwp 0.2?)


app = Flask(__name__, )
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lxcwebpanel.db'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['JWT_EXPIRATION_DELTA'] = timedelta(seconds=10000)
app.config['JWT_AUTH_URL_RULE'] = '/api/v1/auth'

# extensions
db = SQLAlchemy(app)
api = Api(app)
jwt = JWT(app)

# permissions (the import must happen after that call)
perms = Permissions(app, db, current_user)
from flask_lwp_permissions.models import Role, Ability, User, Container
from flask_lwp_permissions.decorators import user_is, user_has
from flask_lwp_permissions.utils import is_user_has

abilities_list = ('users_infos_all','users_create','users_infos','users_update',
                 'users_delete','groups_infos_all','groups_create','groups_infos',
                 'groups_update','groups_delete','ct_infos','ct_create',
                 'ct_update','ct_delete','ct_start','ct_freeze','ct_unfreeze',
                 'ct_stop','ct_restart','lxc_infos','host_stats','host_reboot',
                 'me_edit')

@jwt.error_handler
def error_handler(e):
    return "Something bad happened", 400

@app.before_request
# @jwt_required()
def populate_containers_table():
    current_containers_list = lxc.list_containers()
    database_containers_list = [str(i) for i in Container.query.all()]

    # Removing old containers from database
    for ct in database_containers_list:
        if not ct in current_containers_list:
            container = Container.query.filter_by(name=ct).first()
            db.session.delete(container)

    # Adding new containers to database
    for ct in current_containers_list:
        if not ct in database_containers_list:
            container = Container(name=ct)
            db.session.add(container)

    db.session.commit()


@app.route('/')
def root():
    return make_response(open('templates/index.html').read())

# User API
user_fields = {
    'id': fields.Integer,
    'username': fields.String,
    'name': fields.String,
    'email': fields.String,
    'roles': fields.List(fields.String),
    'containers': fields.List(fields.String)
}


class UsersList(Resource):
    decorators = [jwt_required()]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('username', type=str, required=True,
                                   location='json')
        self.reqparse.add_argument('name', type=str, required=True,
                                   location='json')
        self.reqparse.add_argument('email', type=str, location='json')
        self.reqparse.add_argument('roles', type=list, required=True,
                                   location='json')
        self.reqparse.add_argument('containers', type=list, location='json')
        self.reqparse.add_argument('password', type=str, required=True,
                                   location='json')
        super(UsersList, self).__init__()

    @user_has('users_infos_all')
    def get(self):
        users = User.query.all()

        return {'users': marshal(users, user_fields)}

    @user_has('users_create')
    def post(self):
        args = self.reqparse.parse_args()

        if User.query.filter_by(username=args.username).first():
            return {'error': 'User already exists'}, 409

        user = User()

        user.username = args.username
        user.name = args.name
        user.roles = args.roles


        if args.email:
            user.email = args.email
        if args.containers:
            user.containers = args.containers

        user.hash_password(args.password)

        db.session.add(user)
        db.session.commit()
        args['id'] = user.id

        return {'user': marshal(args, user_fields)}, 201


class Users(Resource):
    decorators = [jwt_required()]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('name', type=str, location='json')
        self.reqparse.add_argument('email', type=str, location='json')
        self.reqparse.add_argument('roles', type=list, location='json')
        self.reqparse.add_argument('containers', type=list, location='json')
        self.reqparse.add_argument('password', type=str, location='json')
        super(Users, self).__init__()

    @user_has('users_infos')
    def get(self, id):
        user = User.query.get(id)

        if not user:
            return {'error': "User not found"}, 404

        return {'user': marshal(user, user_fields)}

    @user_has('users_update')
    def put(self, id):
        user = User.query.get(id)


        if not user:
            return {'error': "User not found"}, 404

        args = self.reqparse.parse_args()

        if args.name:
            user.name = args.name
        if args.roles:
            user.roles = args.roles
        if args.email:
            user.email = args.email
        if args.containers:
            user.containers = args.containers
        if args.password:
            user.hash_password(args.password)

        if len(args) < 0:
            db.session.commit()

        return {'user': marshal(user, user_fields)}

    @user_has('users_delete')
    def delete(self, id):
        user = User.query.get(id)


        print(user.name)
        if not user:
            return {'error': "User not found"}, 404

        db.session.delete(user)
        db.session.commit()

        return {'message': 'User %s deleted' % user.name}, 200


class Me(Resource):
    decorators = [jwt_required()]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('name', type=str, location='json')
        self.reqparse.add_argument('email', type=str, location='json')
        self.reqparse.add_argument('roles', type=list, location='json')
        self.reqparse.add_argument('containers', type=list, location='json')
        self.reqparse.add_argument('password', type=str, location='json')
        super(Me, self).__init__()

    def get(self):
        return {'user': marshal(current_user, user_fields)}

    @user_has('me_edit')
    def put(self):
        user = User.query.get(current_user.id)

        args = self.reqparse.parse_args()

        if args.name:
            user.name = args.name
        if args.roles:
            user.roles = args.roles
        if args.email:
            user.email = args.email
        if args.containers:
            user.containers = args.containers
        if args.password:
            user.hash_password(args.password)

        if len(args) < 0:
            db.session.commit()

        return {'user': marshal(user, user_fields)}

    @user_has('me_edit')
    def delete(self):
        user = User.query.get(current_user.id)

        db.session.delete(user)
        db.session.commit()

        return {'message': 'User %s deleted' % user.name}, 200

# Groups api
group_fields = {
    'id': fields.Integer,
    'name': fields.String,
    'abilities': fields.List(fields.String)
}

class GroupsList(Resource):
    decorators = [jwt_required()]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('name', type=str, required=True,
                                   location='json')
        self.reqparse.add_argument('abilities', type=list, location='json')
        super(GroupsList, self).__init__()

    @user_has('groups_infos_all')
    def get(self):
        roles = Role.query.all()

        return {'groups': marshal(roles, group_fields)}

    @user_has('groups_create')
    def post(self):
        args = self.reqparse.parse_args()
        group = Role(name=args.name)
        if args.abilities:
            for i in args.abilities:
                group.add_abilities(i)
        db.session.add(group)
        db.session.commit()
        args['id'] = group.id

        return {'group': marshal(args, group_fields)}, 201


class Groups(Resource):
    decorators = [jwt_required()]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('name', type=str, required=True,
                                   location='json')
        self.reqparse.add_argument('abilities', type=list, location='json')
        super(Groups, self).__init__()

    @user_has('groups_infos')
    def get(self, id):
        group = Role.query.get(id)

        if not group:
            return {'error': "Group not found"}, 404

        return {'group': marshal(group, group_fields)}

    @user_has('groups_update')
    def put(self, id):
        group = Role.query.get(id)
        args = self.reqparse.parse_args()
        group.name = args.name

        if args.abilities:
            group.remove_abilities('users_infos_all','users_create','users_infos','users_update',
                 'users_delete','groups_infos_all','groups_create','groups_infos',
                 'groups_update','groups_delete','ct_infos','ct_create',
                 'ct_update','ct_delete','ct_start','ct_freeze','ct_unfreeze',
                 'ct_stop','ct_restart','lxc_infos','host_stats','host_reboot',
                 'me_edit')
            for i in args.abilities:
                group.add_abilities(i)

        db.session.commit()

        return {'group': marshal(group, group_fields)}

    @user_has('groups_delete')
    def delete(self, id):
        group = Role.query.get(id)

        if not group:
            return {'error': "Group not found"}, 404

        db.session.delete(group)
        db.session.commit()

        return {'message': 'Group %s deleted' % group.name}, 200



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
            if c in current_user.containers:
                containers.append(lwp.ct_infos(c))

        sorted_dict = sorted(containers, key=lambda k: k['sorted_dict'])
        for ct_dict in sorted_dict:
            del ct_dict['sorted_dict']

        return {'containers': sorted_dict} # Sorted like the frontend

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
        user = User.query.get(current_user.id)
        user.containers.append(args.name)

        if not c.defined:
            if not c.create(template=args.template, args=args.args):
                return {'error': 'Can\'t create container %s!'
                                 % args.name}, 500
            db.session.commit()
            return Containers.get(self, args.name), 201

        return {'error': 'Container %s already exists!' % args.name}, 409


class Containers(Resource):
    decorators = [jwt_required()]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Containers, self).__init__()

    @user_has('ct_infos')
    def get(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_user.containers:
            return lwp.ct_infos(container)

        return {'error': 'Container %s doesn\'t exists!' % container}


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

        if c.defined and container in current_user.containers:
            if args.name and args.name != c.name:
                if not c.rename(args.name):
                    return {'error': 'Can\'t rename container %s to %s!'
                                     % (container, args.name)}

                container = args.name
                c = lxc.Container(container)



            if args.hostname:
                if not c.set_config_item("lxc.utsname", args.hostname):
                    return {'error': 'Can\'t update hostname for %s to %s!'
                            % (container, args.hostname)},500

            if args.memory_limit:
                if not c.set_config_item("lxc.cgroup.memory.limit_in_bytes", str(args.memory_limit * 1048576)): # Convert MB to B
                    return {'error': 'Can\'t update memory limit for %s to %s!'
                            % (container, args.memory_limit)}, 500

            if args.swap_limit:
                if not c.set_config_item("lxc.cgroup.memory.memsw.limit_in_bytes", str(args.swap_limit * 1048576)): # Convert MB to B
                    return {'error': 'Can\'t update swap limit for %s to %s!'
                            % (container, args.memory_limit)}, 500

            if args.start_auto:
                if not c.set_config_item("lxc.start.auto", args.start_auto):
                    return {'error': 'Can\'t set start auto for %s to %s!'
                            % (container, args.start_auto)},500

            if args.start_delay:
                if not c.set_config_item("lxc.start.delay", args.start_delay):
                    return {'error': 'Can\'t set start delay for %s to %s!'
                            % (container, args.start_delay)},500

            if args.start_order:
                if not c.set_config_item("lxc.start.order", args.start_order):
                    return {'error': 'Can\'t set start order for %s to %s!'
                            % (container, args.start_order)},500

            if args.groups:
                if not c.set_config_item("lxc.group", args.groups):
                    return {'error': 'Can\'t set group for %s to %s!'
                            % (container, args.groups)},500

            if args.cpu_shares:
                if not c.set_config_item("lxc.cpu.shares", args.cpu_shares):
                    return {'error': 'Can\'t set cpu shares for %s to %s!'
                            % (container, args.cpu_shares)},500

            if args.cpus:
                if not c.set_config_item("lxc.cpuset.cpus", args.cpus):
                    return {'error': 'Can\'t set start auto for %s to %s!'
                            % (container, args.cpus)},500



            if args.name or args.hostname or args.memory_limit:
                c.save_config()

            return Containers.get(self, container)

        return {'error': 'Container %s doesn\'t exists!' % container}, 404

    @user_has('ct_delete')
    def delete(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_user.containers:
            if c.running:
                if not c.stop():
                    return {'error': 'Can\'t stop container %s!'
                                     % container}, 409
            if not c.destroy():
                return {'error': 'Can\'t destroy container %s!'
                                 % container}, 409
            return {'success': 'Container %s destroyed successfully!' % container}, 200

        return {'error': 'Container %s doesn\'t exists!' % container}, 404


class ContainersStart(Resource):
    decorators = [jwt_required()]

    @user_has('ct_start')
    def post(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_user.containers:
            c.start()
            c.wait('RUNNING', 3)
            return Containers.get(self, container)

        return {'error': 'Container %s doesn\'t exists!' % container}, 404


class ContainersFreeze(Resource):
    decorators = [jwt_required()]

    @user_has('ct_freeze')
    def post(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_user.containers:
            c.freeze()
            c.wait('FROZEN', 3)
            return Containers.get(self, container)

        return {'error': 'Container %s doesn\'t exists!' % container}, 404


class ContainersUnfreeze(Resource):
    decorators = [jwt_required()]

    @user_has('ct_unfreeze')
    def post(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_user.containers:
            c.unfreeze()
            c.wait('RUNNING', 3)
            return Containers.get(self, container)

        return {'error': 'Container %s doesn\'t exists!' % container}, 404


class ContainersStop(Resource):
    decorators = [jwt_required()]

    @user_has('ct_stop')
    def post(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_user.containers:
            c.stop()
            c.wait('STOPPED', 3)
            return Containers.get(self, container)

        return {'error': 'Container %s doesn\'t exists!' % container}, 404


class ContainersShutdown(Resource):
    decorators = [jwt_required()]

    @user_has('ct_stop')
    def post(self, container):
        c = lxc.Container(container)

        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('timeout', type=int, default=10)
        args = self.reqparse.parse_args()

        if c.defined and container in current_user.containers:
            c.shutdown(args.timeout)
            c.wait('STOPPED', 3)
            return Containers.get(self, container)

        return {'error': 'Container %s doesn\'t exists!' % container}, 404


class ContainersRestart(Resource):
    decorators = [jwt_required()]

    @user_has('ct_restart')
    def post(self, container):
        c = lxc.Container(container)

        if c.defined and container in current_user.containers:
            ContainersStop.post(self, container)
            ContainersStart.post(self, container)
            return Containers.get(self, container)

        return {'error': 'Container %s doesn\'t exists!' % container}, 404


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
        config_dict['Multiple /dev/pts instances'] = is_enabled('CONFIG_DEVPTS_MULTIPLE_INSTANCES')
        config_dict['Cgroup'] = is_enabled('CONFIG_CGROUPS', True)
        config_dict['Cgroup namespace'] = is_enabled('CONFIG_CGROUP_NS', True)
        config_dict['Cgroup device'] = is_enabled('CONFIG_CGROUP_DEVICE')
        config_dict['Cgroup sched'] = is_enabled('CONFIG_CGROUP_SCHED')
        config_dict['Cgroup cpu account'] = is_enabled('CONFIG_CGROUP_CPUACCT')

        if kver_major >= 3 and kver_minor >= 6:
            config_dict['Cgroup memory controller'] = is_enabled('CONFIG_MEMCG')
        else:
            config_dict['Cgroup memory controller'] = is_enabled('CONFIG_CGROUP_MEM_RES_CTLR')

        if is_set('CONFIG_SMP'):
            config_dict['Cgroup cpuset'] = is_enabled('CONFIG_CPUSETS')

        config_dict['Veth pair device'] = is_enabled('CONFIG_VETH')
        config_dict['Macvlan'] = is_enabled('CONFIG_MACVLAN')
        config_dict['Vlan'] = is_enabled('CONFIG_VLAN_8021Q')

        if kver_major == 2 and kver_minor < 33:
            config_dict['File capabilities'] = is_enabled('CONFIG_SECURITY_FILE_CAPABILITIES')
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



@jwt.authentication_handler
def authenticate(username, password):
    user = User.query.filter_by(username=username).first()

    if not user or not user.verify_password(password):
        return False

    return user


@jwt.user_handler
def load_user(payload):
    return User.query.get(payload['user_id'])


##############
# API routes #
##############

# Users routes
api.add_resource(UsersList, '/api/v1/users')
api.add_resource(Users, '/api/v1/users/<int:id>')
api.add_resource(Me, '/api/v1/me')
api.add_resource(GroupsList, '/api/v1/groups')
api.add_resource(Groups, '/api/v1/groups/<int:id>')

# LXC templates routes
# api.add_resource(LxcTemplatesList,
#                  '/api/v1/lxc/templates')
# api.add_resource(LxcTemplatesInfos,
#                  '/api/v1/lxc/templates/<string:template>')


# Containers routes
api.add_resource(ContainersList,
                 '/api/v1/containers')
api.add_resource(Containers,
                 '/api/v1/containers/<string:container>')
api.add_resource(ContainersStart,
                 '/api/v1/containers/<string:container>/start')
api.add_resource(ContainersFreeze,
                 '/api/v1/containers/<string:container>/freeze')
api.add_resource(ContainersUnfreeze,
                 '/api/v1/containers/<string:container>/unfreeze')
api.add_resource(ContainersStop,
                 '/api/v1/containers/<string:container>/stop')
api.add_resource(ContainersShutdown,
                 '/api/v1/containers/<string:container>/shutdown')
api.add_resource(ContainersRestart,
                 '/api/v1/containers/<string:container>/restart')

# lxc-chekconfig route
api.add_resource(LxcCheckConfig, '/api/v1/lxc/checkconfig')

# Host routes
api.add_resource(HostStats, '/api/v1/host')
api.add_resource(HostReboot, '/api/v1/host/reboot')

if __name__ == '__main__':
    # port 80 for dev version
    app.run(host='0.0.0.0', port=80, debug=True)
