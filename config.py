import logging, sys, types, os.path, re
from ConfigParser import RawConfigParser, NoOptionError

log = logging.getLogger("rfw.log")

class Config:
    def __init__(self, path, section="config"):
        self.path = path
        self.section = section
        self.parser = RawConfigParser(allow_no_value=True)
        self.parser.read(self.path)

    def _get(self, opt):
        """Get option value from [config] section of config file.
        It may return None if valueless option present (option name only). It's possible because allow_no_value=True
        It may raise NoOptionError if option not present
        """
        return self.parser.get(self.section, opt)


    def _getflag(self, opt, log_msg=""):
        """Return True if valueless option present in config file. False otherwise.
        """
        try:
            #None means that the option is present in the config file
            return self._get(opt) is None
        except NoOptionError:
            #ignore, no such option is a valid case. Optionally log the info message
            if log_msg:
                log.info(log_msg)
        return False


    def _configexit(self, msg):
        """Log config error and exit with error code
        """
        log.error("Configuration error in {}: {}".format(self.path, msg))
        print("Configuration error in {}: {}".format(self.path, msg))
        sys.exit(1)

class RfwConfig(Config):

    def __init__(self, path):
        Config.__init__(self, path)
        self._whitelist = None
        
        # Fail early validations. Read all properties to validate and show config dependencies
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
        self.chain_input_action()
        self.chain_output_action()
        self.chain_forward_action()
        self.whitelist_file()
        self.whitelist()  # it will also cache the whitelist result
            
 
    
    # IP address format validator
    # return validated (and trimmed) IP address or False if not valid
    def _validate_ip(self, ip):
        if not ip:
            return False
        ip = ip.strip()
        #TODO check if ^ is acceptable in regexp here
        m = re.match(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
        if m:
            if int(m.group(1)) < 256 and int(m.group(2)) < 256 and int(m.group(3)) < 256 and int(m.group(4)) < 256:
                return ip
        return False

    # Port number format validator
    # return validated port number as string or False if not valid
    def _validate_port(self, port):
        if not port:
            return False
        port = port.strip()
        if port.isdigit() and int(port) > 0 and int(port) < 65536:
            return port
        return False


    def is_outward_server(self):
        return self._getflag("outward.server", "outward.server not enabled. Ignoring outward.server.port and outward.server.ip if present.")
    
    def outward_server_port(self):
        if self.is_outward_server():
            try:
                port = self._get("outward.server.port")
                if port and self._validate_port(port):
                    return port
                else:
                    self._configexit("Wrong outward.server.port value. It should be a single number from the 1..65535 range")
            except NoOptionError, e:
                self._configexit(str(e))
        else:
            msg = "outward.server.port read while outward.server not enabled"
            self._configexit(msg)
    
    
    def outward_server_ip(self):
        if self.is_outward_server():
            try:
                return self._get("outward.server.ip")
            except NoOptionError, e:
                self._configexit(str(e))
        else:
            msg = "outward.server.ip read while outward.server not enabled"
            self._configexit(msg)
    
    def is_local_server(self):
        return self._getflag("local.server", "local.server not enabled. Ignoring local.server.port if present.")
    
    
    def local_server_port(self):
        if self.is_local_server():
            try:
                port = self._get("local.server.port")
                if port and self._validate_port(port):
                    return port
                else:
                    self._configexit("Wrong local.server.port value. It should be a single number from the 1..65535 range")
            except NoOptionError, e:
                self._configexit(str(e))
        else:
            msg = "local.server.port read while local.server not enabled"
            self._configexit(msg)
    
    def is_non_restful(self):
        return self._getflag("non.restful")
    
    def is_local_server_authentication(self):
        if self.is_local_server():
            try:
                return self._getflag("local.server.authentication")
            except NoOptionError, e:
                self._configexit(str(e))
        else:
            msg = "local.server.authentication read while local.server not enabled"
            self._configexit(msg)
    
    
    def auth_username(self):
        if self.is_outward_server() or self.is_local_server_authentication():
            try:
                username = self._get("auth.username")
                if username:
                    return username
                else:
                    self._configexit("auth.username cannot be empty")
            except NoOptionError, e:
                self._configexit(str(e))
        else:
            msg = "auth.username read while outward.server not enabled and local.server.authentication not enabled"
            self._configexit(msg)
    
    
    def auth_password(self):
        if self.is_outward_server() or self.is_local_server_authentication():
            try:
                password = self._get("auth.password")
                if password:
                    return password
                else:
                    self._configexit("auth.password cannot be empty")
            except NoOptionError, e:
                self._configexit(str(e))
        else:
            msg = "auth.password read while outward.server not enabled and local.server.authentication not enabled"
            self._configexit(msg)
   
    def _chain_action(self, name):
        try:
            action = self._get(name)
            if action:
                action = action.upper()
                if action in ['DROP', 'ACCEPT']:
                    return action
                self._configexit("allowed values for {} are DROP or ACCEPT".format(name))
            else:
                self._configexit("{} cannot be empty. Allowed values are DROP or ACCEPT".format(name))
        except NoOptionError, e:
            self._configexit(str(e))


    def chain_input_action(self):
        return self._chain_action('chain.input.action')

    def chain_output_action(self):
        return self._chain_action('chain.output.action')

    def chain_forward_action(self):
        return self._chain_action('chain.forward.action')

   
    def whitelist_file(self):
        try:
            return self._get("whitelist.file")
        except NoOptionError, e:
            self._configexit(str(e))

    # return cached list of whitelist IP addresses
    def whitelist(self):
        #TODO not thread safe but this method is initialized from constructor so it should be fine
        if self._whitelist is None:
            wfile = self.whitelist_file()
            if not os.path.isfile(wfile):
                self._configexit("Could not read {} file".format(wfile))
            with open(wfile) as f:
                lines = f.readlines()
            ips = [self._validate_ip(line) for line in lines if line.strip() and not line.strip().startswith('#')]
            if False in ips:
                self._configexit("Wrong IP address format in {}".format(wfile))
            if not ips:
                self._configexit("Could not find a valid IP address in {}".format(wfile))
            self._whitelist = ips
        return self._whitelist



# test particular config file. Results must be compared manually
if __name__ == "__main__":

    #TODO write more generic tests
    rfwconf = RfwConfig("rfw.conf")

    print(rfwconf.auth_password())

    module = sys.modules[__name__]
    # take all attributes of the module
    attrs = [getattr(module, name, None) for name in dir()]
    # filter for function without arguments
    #fs = filter(lambda a: isinstance(a, types.FunctionType) and a.func_code.co_argcount == 0, attrs)
    fs = [a for a in attrs if isinstance(a, types.FunctionType) and a.func_code.co_argcount == 0]
    for f in fs:
        print("%s = %s" % (f.__name__, f()))




