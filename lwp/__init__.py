#!/usr/bin/env python
# -*- coding: utf-8 -*-
import lxc
import platform
import re
import subprocess
import time
import os
import configparser


def _run(cmd, output=False):
    '''
    To run command easier
    '''
    if output:
        try:
            out = subprocess.check_output('{}'.format(cmd), shell=True)
        except subprocess.CalledProcessError:
            out = False
        return out

    if int(subprocess.check_call('{}'.format(cmd), shell=True)) == 0:
        return True
    else:
        return False


def ct_infos(container, id=None):
    c = lxc.Container(container)

    def get_config(c, config_item, default=None):
        if config_item.startswith('lxc.cgroup'):
            cgroup = '.'.join(config_item.split('.')[2:])
            try:
                value = c.get_cgroup_item(cgroup)
                if value == '':
                    value = default
                try:
                    if value.isdigit():
                        value = int(value)
                except AttributeError:
                    if not isinstance(value, list):
                        value = default
                return value
            except KeyError:
                pass
        try:
            value = c.get_config_item(config_item)
            if value == 'NOTSET' or value == '':
                value = default
            try:
                if value.isdigit():
                    value = int(value)
            except AttributeError:
                if not isinstance(value, list):
                    value = default
        except KeyError:
            value = default
        return value

    network = []

    for i in range(len(c.get_config_item('lxc.network'))):
        network.append(
            {
                'flags': get_config(c, 'lxc.network.%s.flags' % i),
                'hwaddr': get_config(c, 'lxc.network.%s.hwaddr' % i),
                'ipv4': {
                    '_': get_config(c, 'lxc.network.%s.ipv4' % i),
                    'gateway': get_config(c, 'lxc.network.%s.ipv4.gateway' % i)
                },
                'ipv6': {
                    '_': get_config(c, 'lxc.network.%s.ipv6' % i),
                    'gateway': get_config(c, 'lxc.network.%s.ipv6.gateway' % i)
                },
                'link': get_config(c, 'lxc.network.%s.link' % i),
                'macvlan': {
                    'mode': get_config(c, 'lxc.network.%s.macvlan.mode' % i)
                },
                'mtu': get_config(c, 'lxc.network.%s.mtu' % i),
                'name': get_config(c, 'lxc.network.%s.name' % i),
                'script': {
                    'down': get_config(c, 'lxc.network.%s.script.down' % i),
                    'up': get_config(c, 'lxc.network.%s.script.up' % i)
                },
                'type': get_config(c, 'lxc.network.%s.type' % i),
                'veth': {
                    'pair': get_config(c, 'lxc.network.%s.veth.pair' % i)
                },
                'vlan': {
                    'id': get_config(c, 'lxc.network.%s.vlan.id' % i)
                }
            }
        )

    infos = {
        'name': c.name,
        'id': id,
        'pid': c.init_pid,
        'state': c.state,
        'lxc': {
            'aa_allow_incomplete': get_config(c, 'lxc.aa_allow_incomplete', default=0),
            'aa_profile': get_config(c, 'lxc.aa_profile'),
            'arch': get_config(c, 'lxc.arch'),
            'autodev': get_config(c, 'lxc.autodev', default=1),
            'cap': {
                'drop': get_config(c, 'lxc.cap.drop', default=[]),
                'keep': get_config(c, 'lxc.cap.keep', default=[])
            },
            'cgroup': {
                'cpu': {
                    'shares': get_config(c, 'lxc.cgroup.cpu.shares', default=1024)
                },
                'cpuset': {
                    'cpus': get_config(c, 'lxc.cgroup.cpuset.cpus', default=[])
                },
                'memory': {
                    'limit_in_bytes': get_config(c, 'lxc.cgroup.memory.limit_in_bytes'),
                    'memsw': {
                        'limit_in_bytes': get_config(c, 'lxc.cgroup.memory.memsw.limit_in_bytes')
                    }
                }
            },
            'console': {
                '_': get_config(c, 'lxc.console'),
                'logfile': get_config(c, 'lxc.console.logfile')
            },
            'devttydir': get_config(c, 'lxc.devttydir'),
            'environment': get_config(c, 'lxc.environment', default=[]),
            'ephemeral': get_config(c, 'lxc.ephemeral', default=0),
            'group': get_config(c, 'lxc.group', default=[]),
            'haltsignal': get_config(c, 'lxc.haltsignal', default='SIGPWR'),
            'hook': {
                'autodev': get_config(c, 'lxc.hook.autodev', default=[]),
                'clone': get_config(c, 'lxc.hook.clone', default=[]),
                'destroy': get_config(c, 'lxc.hook.destroy', default=[]),
                'mount': get_config(c, 'lxc.hook.mount', default=[]),
                'post-stop': get_config(c, 'lxc.hook.post-stop', default=[]),
                'pre-mount': get_config(c, 'lxc.hook.pre-mount', default=[]),
                'pre-start': get_config(c, 'lxc.hook.pre-start', default=[]),
                'start': get_config(c, 'lxc.hook.start', default=[]),
                'stop': get_config(c, 'lxc.hook.stop', default=[])
            },
            'id_map': get_config(c, 'lxc.id_map'),
            'include': get_config(c, 'lxc.include'),
            'init_cmd': get_config(c, 'lxc.init_cmd'),
            'init_gid': get_config(c, 'lxc.init_gid', default=0),
            'init_uid': get_config(c, 'lxc.init_uid', default=0),
            'kmsg': get_config(c, 'lxc.kmsg', default=0),
            'logfile': get_config(c, 'lxc.logfile'),
            'loglevel': get_config(c, 'lxc.loglevel', default=5),
            'monitor': {
                'unshare': get_config(c, 'lxc.monitor.unshare', default=0)
            },
            'mount': {
                '_': get_config(c, 'lxc.mount'),
                'auto': get_config(c, 'lxc.mount.auto'),
                'entry': get_config(c, 'lxc.mount.entry', default=[])
            },
            'network': network,
            'no_new_privs': get_config(c, 'lxc.no_new_privs', default=0),
            'pts': get_config(c, 'lxc.pts'),
            'rebootsignal': get_config(c, 'lxc.rebootsignal', default='SIGINT'),
            'rootfs': {
                '_': get_config(c, 'lxc.rootfs'),
                'backend': get_config(c, 'lxc.rootfs.mount'),
                'mount': get_config(c, 'lxc.rootfs.options'),
                'options': get_config(c, 'lxc.rootfs.backend')
            },
            'se_context': get_config(c, 'lxc.se_context'),
            'seccomp': get_config(c, 'lxc.seccomp'),
            'start': {
                'auto': get_config(c, 'lxc.start.auto', default=0),
                'delay': get_config(c, 'lxc.start.delay'),
                'order': get_config(c, 'lxc.start.order')
            },
            'stopsignal': get_config(c, 'lxc.stopsignal', default='SIGKILL'),
            'syslog': get_config(c, 'lxc.syslog'),
            'tty': get_config(c, 'lxc.tty'),
            'utsname': get_config(c, 'lxc.utsname')
        }
    }

    return infos


def host_disk_usage(partition='/'):
    '''
    returns a dict of disk usage values in megabytes
    '''
    usage = _run('df -m %s | tail -n -1' % partition,
                 output=True).decode("utf-8").split()

    return dict(disk=usage[0],
                total=int(usage[1]),
                used=int(usage[2]),
                free=int(usage[3]),
                percent=int(usage[4].strip('%')))


def host_cpu_infos():
    f = open('/proc/cpuinfo', 'r')
    l = f.read()
    f.close()
    i = l.index('model name')
    name = l[i:].split(None, 3)[3].split('\n')[0]

    i = l.index('cpu cores')
    cores = l[i:].split(None, 3)[3].split('\n')[0]

    return dict(name=name, cores=cores)


def host_cpu_percent():
    '''
    returns CPU usage in percent
    '''
    f = open('/proc/stat', 'r')
    line = f.readlines()[0]
    data = line.split()
    previdle = float(data[4])
    prevtotal = float(data[1]) + float(data[2]) + float(data[3]) + \
        float(data[4])
    f.close()
    time.sleep(0.1)
    f = open('/proc/stat', 'r')
    line = f.readlines()[0]
    data = line.split()
    idle = float(data[4])
    total = float(data[1]) + float(data[2]) + float(data[3]) + float(data[4])
    f.close()

    intervaltotal = total - prevtotal
    try:
        percent = 100 * (intervaltotal - (idle - previdle)) / intervaltotal
    except ZeroDivisionError:
        percent = 0

    return float('%.1f' % percent)


def host_memory_usage():
    '''
    returns a dict of host memory usage values
                    {'percent': int((used/total)*100),
                    'percent_cached':int((cached/total)*100),
                    'swap': int(swap/1024),
                    'used': int(used/1024),
                    'total': int(total/1024)}
    '''
    out = open('/proc/meminfo', 'r')
    total = free = buffers = cached = 0
    for line in out:
        if 'MemTotal:' == line.split()[0]:
            split = line.split()
            total = float(split[1])
        if 'MemFree:' == line.split()[0]:
            split = line.split()
            free = float(split[1])
        if 'Buffers:' == line.split()[0]:
            split = line.split()
            buffers = float(split[1])
        if 'Cached:' == line.split()[0]:
            split = line.split()
            cached = float(split[1])
        if 'SwapTotal:' == line.split()[0]:
            split = line.split()
            swap_total = float(split[1])
        if 'SwapFree:' == line.split()[0]:
            split = line.split()
            swap_free = float(split[1])
        if 'SwapCached:' == line.split()[0]:
            split = line.split()
            swap_cached = float(split[1])

    out.close()
    used = (total - (free + buffers + cached))
    swap_used = (swap_total - (swap_free + swap_cached))
    return {'percent': int(used * 100 / total),
            'percent_cached': int(cached * 100 / total),
            'swap_percent': int(swap_used * 100 / swap_total),
            'swap_used': int(swap_used / 1024),
            'swap_total': int(swap_total / 1024),
            'used': int(used / 1024),
            'total': int(total / 1024)}


def host_uptime():
    '''
    returns a dict of the system uptime
            {'day': days,
            'time': '%d:%02d' % (hours,minutes)}
    '''
    f = open('/proc/uptime')
    uptime = int(f.readlines()[0].split('.')[0])
    minutes = uptime / 60 % 60
    hours = uptime / 60 / 60 % 24
    days = uptime / 60 / 60 / 24
    f.close()
    return {'day': '%01d' % days,
            'time': '%d:%02d' % (hours, minutes)}


def host_kernel_verion():
    uname = platform.uname()
    data = '%s %s %s' % (uname[0], uname[2], uname[3])
    return data


def get_templates_list():
    '''
    returns a sorted lxc templates list
    '''
    templates = []
    path = None

    templates_path = '/usr/share/lxc/templates'
    if os.path.exists(templates_path) and os.path.isdir(templates_path):
        path = os.listdir(templates_path)
    else:
        templates_path = '/usr/lib/lxc/templates'  # Compat
        if os.path.exists(templates_path) and os.path.isdir(templates_path):
            path = os.listdir(templates_path)

    if path:
        for line in path:
            templates.append(line.replace('lxc-', ''))

    return sorted(templates)


def get_template_options(template):
    '''
    Get lxc template options: arch & releases
    '''
    result = {
        "arch": [],
        "releases": [],
        "system": {
            "arch": platform.machine(),
            "release": platform.linux_distribution()[2],
        }
    }

    # XXX: some distros arch not equal to system arch...
    # Dunno what to do, maybe aliases in templates.conf...
    if result["system"]["arch"] == "x86_64":
        if platform.linux_distribution()[0] in ('Debian', 'Ubuntu'):
            result["system"]["arch"] = 'amd64'

    if not os.path.isfile('templates.conf'):
        return result

    config = configparser.SafeConfigParser(allow_no_value=True)
    config.readfp(open('templates.conf'))

    if config.has_section(template):
        if config.has_option(template, 'releases'):
            result['releases'].extend(config.get(
                template, 'releases').split(','))
    elif config.has_section('default'):
        if config.has_option('default', 'releases'):
            result['releases'].extend(config.get(
                'default', 'releases').split(','))

    return result
