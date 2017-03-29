"""Metrics reported for each process running under Supervisor"""

from __future__ import absolute_import, division

import functools

import psutil

import supermann.utils


def running_process(function):
    """Decorates a signals.process reciver to only run if the process exists"""
    @functools.wraps(function)
    def wrapper(sender, process, data):
        if process is None:
            log = supermann.utils.getLogger(function)
            log.debug("Process '{0}' does not exist (state: {1})".format(
                data['full_name'], data['statename']))
        else:
            return function(sender, process, data)
    return wrapper


def get_nofile_limit(pid):
    """Returns the NOFILE limit for a given PID

    :param int pid: The PID of the process
    :returns: (*int*) The NOFILE limit
    """
    with open('/proc/%s/limits' % pid, 'r') as f:
        for line in f:
            if line.startswith('Max open files'):
                return int(line.split()[4])
    raise RuntimeError('Could not find "Max open files" limit')


@running_process
def cpu(sender, process, data):
    """CPU utilisation as a percentage and total CPU time in seconds

    - ``process:{full_name}:cpu:percent``
    - ``process:{full_name}:cpu:absolute``
    """
    sender.riemann.event(
        service='process:{full_name}:cpu:percent'.format(**data),
        metric_f=process.cpu_percent(interval=None))
    sender.riemann.event(
        service='process:{full_name}:cpu:absolute'.format(**data),
        metric_f=sum(process.cpu_times()))


@running_process
def mem(sender, process, data):
    """Total virtual memory, total RSS memory, RSS utilisation as percentage

    - ``process:{full_name}:mem:virt:absolute``
    - ``process:{full_name}:mem:rss:absolute``
    - ``process:{full_name}:mem:rss:percent``
    """
    memory_info = process.memory_info()
    sender.riemann.event(
        service='process:{full_name}:mem:virt:absolute'.format(full_name=data['full_name']),
        metric_f=memory_info.vms)
    sender.riemann.event(
        service='process:{full_name}:mem:rss:absolute'.format(full_name=data['full_name']),
        metric_f=memory_info.rss)
    sender.riemann.event(
        service='process:{full_name}:mem:rss:percent'.format(full_name=data['full_name']),
        metric_f=process.memory_percent())


@running_process
def fds(sender, process, data):
    """Number of file descriptors a process is using it's hard limit

    - ``process:{full_name}:fds:absolute``
    - ``process:{full_name}:fds:percent``
    """
    num_fds = process.num_fds()
    sender.riemann.event(
        service='process:{full_name}:fds:absolute'.format(**data),
        metric_f=num_fds)
    sender.riemann.event(
        service='process:{full_name}:fds:percent'.format(**data),
        metric_f=(num_fds / get_nofile_limit(process.pid)) * 100)


@running_process
def io(sender, process, data):
    """Bytes read and written by a process.

    If ``/proc/[pid]/io`` is not availible (i.e. you are running Supermann
    inside an unprivileged Docker container), the events will have set
    ``metric_f`` to 0 and ``state`` to ``access denied``.

    - ``process:{full_name}:io:read:bytes``
    - ``process:{full_name}:io:write:bytes``
    """
    try:
        io_counters = process.io_counters()
    except psutil.AccessDenied:
        read_bytes = write_bytes = dict(state="access denied")
    else:
        read_bytes = dict(metric_f=io_counters.read_bytes)
        write_bytes = dict(metric_f=io_counters.write_bytes)

    sender.riemann.event(
        service='process:{full_name}:io:read:bytes'.format(**data), **read_bytes)
    sender.riemann.event(
        service='process:{full_name}:io:write:bytes'.format(**data), **write_bytes)


def state(sender, process, data):
    """The process state that Supervisor reports

    - ``process:{full_name}:state``
    """
    sender.riemann.event(
        service='process:{full_name}:state'.format(**data),
        state=data['statename'].lower())


def uptime(sender, process, data):
    """The time in seconds Supervisor reports the process has been running

    - ``process:{full_name}:uptime``
    """
    sender.riemann.event(
        service='process:{full_name}:uptime'.format(**data),
        metric_f=data['stop' if process is None else 'now'] - data['start'])
