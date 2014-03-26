#!/usr/bin/env python
#
# Copyrite (c) 2014 SecurityKISS Ltd (http://www.securitykiss.com)  
#
# This file is part of rfw
#
# The MIT License (MIT)
#
# Yes, Mr patent attorney, you have nothing to do here. Find a decent job instead. 
# Fight intellectual "property".
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import logging, sys, types, os.path, re
import config, iputil, timeutil
from ConfigParser import NoOptionError

log = logging.getLogger('rfw.rfwconfig')

class RfwConfig(config.Config):

    def __init__(self, path):
        self._whitelist = None
        
        try:
            config.Config.__init__(self, path)

            # Fail early validations. Read all properties to validate and show config dependencies
            # Also display a short error message for the user instead of full stacktrace
            if self.is_outward_server():
                self.outward_server_port()
                self.outward_server_ip()
            if self.is_local_server():
                self.local_server_port()
                self.is_local_server_authentication()
            self.is_non_restful()
            if self.is_outward_server() or self.is_local_server_authentication():
                self.auth_username()
                self.auth_password()
            self.whitelist_file()
            self.whitelist()  # it will also cache the whitelist result
            self.iptables_path()
            self.default_expire()
        except config.ConfigError, e:
            log.error(str(e))
            sys.exit(1)
        except Exception, e:
            # other errors need to be wrapped to include the config file path info
            log.error(self.config_error(str(e)))
            sys.exit(1)            

        try:
            # provide more info for these options if not given correctly
            if self.is_outward_server():
                self.outward_server_certfile()
                self.outward_server_keyfile()
        except config.ConfigError, e:
            log.error(str(e))
            log.error('Before running rfw you must generate or import certificates. See /etc/rfw/deploy/README.rst')
            sys.exit(1)
 

 

    def is_outward_server(self):
        return self._getflag("outward.server", "outward.server not enabled. Ignoring outward.server.port and outward.server.ip if present.")
    
    def outward_server_port(self):
        if self.is_outward_server():
            port = self._get("outward.server.port")
            if port and iputil.validate_port(port):
                return port
            else:
                raise self.config_error("Wrong outward.server.port value. It should be a single number from the 1..65535 range")
        else:
            self.config_error("outward.server.port read while outward.server not enabled")
    
    
    def outward_server_ip(self):
        if self.is_outward_server():
            try:
                return self._get("outward.server.ip")
            except NoOptionError, e:
                raise self.config_error(str(e))
        else:
            raise self.config_error("outward.server.ip read while outward.server not enabled")
    
    def outward_server_certfile(self):
        if self.is_outward_server():
            return self._getfile("outward.server.certfile")
        else:
            raise self.config_error("outward.server.certfile read while outward.server not enabled")
 

    def outward_server_keyfile(self):
        if self.is_outward_server():
            return self._getfile("outward.server.keyfile")
        else:
            raise self.config_error("outward.server.keyfile read while outward.server not enabled")


    def is_local_server(self):
        return self._getflag("local.server", "local.server not enabled. Ignoring local.server.port if present.")
    
    
    def local_server_port(self):
        if self.is_local_server():
            try:
                port = self._get("local.server.port")
                if port and iputil.validate_port(port):
                    return port
                else:
                    raise self.config_error("Wrong local.server.port value. It should be a single number from the 1..65535 range")
            except NoOptionError, e:
                raise self.config_error(str(e))
        else:
            raise self.config_error("local.server.port read while local.server not enabled")
    
    def is_non_restful(self):
        return self._getflag("non.restful")
    
    def is_local_server_authentication(self):
        if self.is_local_server():
            return self._getflag("local.server.authentication")
        else:
            raise self.config_error("local.server.authentication read while local.server not enabled")
    
    
    def auth_username(self):
        if self.is_outward_server() or self.is_local_server_authentication():
            try:
                username = self._get("auth.username")
                if username:
                    return username
                else:
                    raise self.config_error("auth.username cannot be empty")
            except NoOptionError, e:
                raise self.config_error(str(e))
        else:
            raise self.config_error("auth.username read while outward.server not enabled and local.server.authentication not enabled")
    
    
    def auth_password(self):
        if self.is_outward_server() or self.is_local_server_authentication():
            try:
                password = self._get("auth.password")
                if password:
                    return password
                else:
                    raise self.config_error("auth.password cannot be empty")
            except NoOptionError, e:
                raise self.config_error(str(e))
        else:
            raise self.config_error("auth.password read while outward.server not enabled and local.server.authentication not enabled")
   
    def _chain_action(self, name):
        try:
            action = self._get(name)
            if action:
                action = action.upper()
                if action in ['DROP', 'ACCEPT']:
                    return action
                raise self.config_error("allowed values for {} are DROP or ACCEPT".format(name))
            else:
                raise self.config_error("{} cannot be empty. Allowed values are DROP or ACCEPT".format(name))
        except NoOptionError, e:
            raise self.config_error(str(e))


    def whitelist_file(self):
        return self._getfile("whitelist.file")


    # return cached list of whitelist IP address ranges in CIDR format or individual IP addresses.
    # TODO allow IP ranges with hyphen, cidrize all including individual IPs
    def whitelist(self):
        #TODO not thread safe but this method is initialized from constructor so it should be fine
        if self._whitelist is None:
            wfile = self.whitelist_file()
            with open(wfile) as f:
                lines = f.readlines()
            #TODO allow IP ranges: xxx.xxx.xxx.xxx-yyy.yyy.yyy.yyy - need to cidrize, see IpNet.php
            ips = [iputil.validate_ip_cidr(line, allow_no_mask=True) for line in lines if line.strip() and not line.strip().startswith('#')]
            if False in ips:
                raise self.config_error("Wrong IP address format in {}".format(wfile))
            if not ips:
                raise self.config_error("Could not find a valid IP address in {}".format(wfile))
            self._whitelist = ips
        return self._whitelist


    def iptables_path(self):
        ipt = self._get('iptables.path')
        if ipt:
            return ipt
        else:
            raise self.config_error("iptables.path cannot be empty")


    def default_expire(self):
        """return parsed default.expire in seconds as string
        """
        exp = self._get('default.expire')
        if not exp:
            raise self.config_error("default.expire missing")
        interval = timeutil.parse_interval(exp)
        if interval is None:
            raise self.config_error("default.expire missing or incorrect format")
        else:
            return str(interval)



