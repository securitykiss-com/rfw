import os, io
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


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
    scripts = ['bin/rfw',],
    data_files = [('/etc/rfw', ['config/rfw.conf'])],
    include_package_data=True,
    long_description=read('README.rst', 'CHANGES.txt'),
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

# TODO create symlink in bin folder

# TODO add info 'Now run deployment scripts to generate certificates and keys'

# TODO openssl why genrsa generates only private key?

# TODO Tutorial on sk website on how to import root CA certificate in Firefox/Chrome

# TODO article on OCSP privacy concern - even if you secure DNS, your browsing habits are revealed to ISP



