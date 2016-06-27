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


def ct_infos(container):
    c = lxc.Container(container)

    state = c.state
    networks = []
    memory_usage = 0

    # Try to get memory limit by cgroup (started container) or by config (not always set)
    try:
        memory_limit = int(c.get_cgroup_item('memory.limit_in_bytes'))
        if memory_limit == 18446744073709551615:
            memory_limit = -1
        else:
            memory_limit = memory_limit/1048576
    except KeyError:
        try:
            memory_limit = int(c.get_config_item('lxc.cgroup.memory.limit_in_bytes')[0])/1048576
        except IndexError:
            memory_limit = -1

    # Get swap limit
    try:
        swap_limit = int(c.get_cgroup_item('memory.memsw.limit_in_bytes'))/1048576
    except KeyError:
        try:
            swap_limit = int(c.get_config_item('lxc.cgroup.memory.memsw.limit_in_bytes')[0])/1048576
        except IndexError:
            swap_limit = -1

    # Get cpu shares
    try:
        cpu_shares = int(c.get_cgroup_item('cpu.shares'))
    except KeyError:
        try:
            cpu_shares = int(c.get_config_item('lxc.cgroup.cpu.shares')[0])
        except IndexError:
            cpu_shares = 1024

    # Get cpus
    try:
        cpus = c.get_cgroup_item('cpuset.cpus')
    except KeyError:
        try:
            cpus = c.get_config_item('lxc.cgroup.cpuset.cpus')[0]
        except IndexError:
            cpus = "0"

    # Get groups
    try:
        groups = c.get_config_item('lxc.group')[0].split(',')
    except IndexError:
        groups = []


    if state == 'RUNNING':
        interfaces = c.get_interfaces()
        ips = c.get_ips()

        for i in range(0, len(c.get_interfaces())-1):
            networks.append({'interface': interfaces[i], 'address': ips[i]})
        sorted_dict=1

    if state == 'FROZEN':
        sorted_dict=2

    if state == 'STOPPED':
        sorted_dict=3

    if re.match('RUNNING|FROZEN', state):
        # CT memory usage in MB
        memory_usage = int(c.get_cgroup_item('memory.usage_in_bytes'))/1048576

    return dict(name=c.name,
                hostname=c.get_config_item('lxc.utsname'),
                rootfs=c.get_config_item('lxc.rootfs'),
                arch=c.get_config_item('lxc.arch'),
                start_auto=int(c.get_config_item('lxc.start.auto')),
                start_delay=int(c.get_config_item('lxc.start.delay')),
                start_order=int(c.get_config_item('lxc.start.order')),
                state=state,
                groups=groups,
                pid=c.init_pid,
                networks=networks,
                memory_usage=memory_usage,
                memory_limit=memory_limit,
                swap_limit=swap_limit,
                cpu_shares=cpu_shares,
                cpus=cpus,
                sorted_dict=sorted_dict)


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
    return {'percent': int(used*100/total),
            'percent_cached': int(cached*100/total),
            'swap_percent': int(swap_used*100/swap_total),
            'swap_used': int(swap_used/1024),
            'swap_total': int(swap_total/1024),
            'used': int(used/1024),
            'total': int(total/1024)}


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
        templates_path = '/usr/lib/lxc/templates' # Compat
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
        "arch" : [],
        "releases" : [],
        "system" : {
            "arch" : platform.machine(),
            "release" : platform.linux_distribution()[2],
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
            result['releases'].extend( config.get(template, 'releases').split(',') )
    elif config.has_section('default'):
        if config.has_option('default', 'releases'):
            result['releases'].extend( config.get('default', 'releases').split(',') )

    return result