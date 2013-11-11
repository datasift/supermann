"""
Supervisor event hierarchy

http://supervisord.org/events.html
"""

from __future__ import print_function

import sys


def build_subclass_dict(base):
    subclasses = {cls.__name__: cls for cls in base.__subclasses__()}

    for name, cls in subclasses.items():
        subclasses.update(build_subclass_dict(cls))

    return subclasses


class PayloadAttribute(object):
    def __init__(self, name):
        self.name = name

    def __get__(self, instance, owner):
        return instance.payload[self.name]


class Event(object):

    @classmethod
    def create(cls, headers, payload):
        subclasses = build_subclass_dict(cls)
        if headers['eventname'] in subclasses:
            cls = subclasses[headers['eventname']]
        return cls(headers, payload)

    def __init__(self, headers, payload):
        self.headers = headers
        self.payload = payload

    @property
    def eventname(self):
        return self.headers['eventname']

    def __repr__(self):
        return "<{0} {1}>".format(
            self.eventname,
            ' '.join([':'.join(item) for item in self.payload.items()]))


class Process_State(Event):
    name = PayloadAttribute('processname')
    group = PayloadAttribute('groupname')
    from_state = PayloadAttribute('from_state')


class Tick(Event):
    when = PayloadAttribute('when')


class Tick_5(Tick):
    frequency = 5


class Tick_60(Tick):
    frequency = 60


class Tick_3600(Tick):
    frequency = 3600
