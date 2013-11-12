"""Supermann package metadata"""

from __future__ import absolute_import, unicode_literals

import setuptools

setuptools.setup(
    name = "supermann",
    version = '0.1.0',

    author = "Sam Clements",
    author_email = "sam.clements@datasift.com",

    url = "https://github.com/borntyping/supermann",
    description = "A Supervisor event listener for Riemann",
    long_description = open('README.rst').read(),

    packages = setuptools.find_packages(),

    install_requires = [
        'supervisor'
    ],

    entry_points = {
        'console_scripts': [
            'supermann = supermann:main'
        ]
    },

    classifiers = [
        'Development Status :: 3 - Alpha',
        'Environment :: No Input/Output (Daemon)',
        'License :: OSI Approved',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Unix',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Logging',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration'
    ],
)