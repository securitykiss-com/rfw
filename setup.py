import os
from setuptools import setup

# Utility function to read the README file used for long description.
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "rfw",
    version = "0.0.1",
    author = "SecurityKISS Ltd",
    author_email = "open.source@securitykiss.com",
    description = ("Remote firewall as a web service. REST API for iptables."),
    license = "MIT",
    keywords = "rfw remote firewall iptables REST web service drop accept ban allow whitelist fail2ban",
    url = "https://github.com/securitykiss-com/rfw",
    packages=['rfw_service'],
    long_description=read('README.md'),
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
