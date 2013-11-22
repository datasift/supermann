"""Utility functions used in other parts of Supermann"""

from __future__ import absolute_import, unicode_literals

import logging


class NullHandler(logging.Handler):
    def emit(self, record):
        pass

logging.getLogger('supermann').addHandler(NullHandler())


def fullname(obj):
    """Returns the qualified name of an object's class"""
    return '.'.join([obj.__module__, obj.__class__.__name__])


def getLogger(obj):
    """Returns a logger using the full name of the given object"""
    return logging.getLogger(fullname(obj))