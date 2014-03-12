#!/usr/bin/env python

import os, io
import distutils.core
from distutils.command.install import install
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# post install hook
class post_install(install):
    def run(self):
        # call parent
        install.run(self)
        # custom post install message
        print('\nBefore running rfw you must generate or import certificates. See /etc/rfw/deploy/README.rst\n')



# Utility function to read the README file used for long description.
#def read(fname):
#    return open(os.path.join(os.path.dirname(__file__), fname)).read()

def read(*filenames, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in filenames:
        fpath = os.path.join(os.path.dirname(__file__), filename)
        with io.open(fpath, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)



setup(
    name = "rfw",
    version = "0.0.1",
    author = "SecurityKISS Ltd",
    author_email = "open.source@securitykiss.com",
    description = ("Remote firewall as a web service. REST API for iptables."),
    license = "MIT",
    keywords = "rfw remote firewall iptables REST web service drop accept ban allow whitelist fail2ban",
    url = "https://github.com/securitykiss-com/rfw",
    packages = ['rfw_service'],
    scripts = ['bin/rfw'],
    data_files = [('/etc/rfw', ['config/rfw.conf', 'config/white.list']), ('/etc/rfw/deploy', ['config/deploy/rfwgen', 'config/deploy/README.rst'])],
    long_description = read('README.rst', 'CHANGES.txt'),
    cmdclass = {'install': post_install},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
    ],
)



