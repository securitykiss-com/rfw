import logging, sys, types, os.path, re
from ConfigParser import RawConfigParser, NoOptionError

# Follow the logging convention:
# - Modules intended as reusable libraries have names 'lib.<modulename>' what allows to configure single parent 'lib' logger for all libraries in the consuming application
# - Add NullHandler (since Python 2.7) to prevent error message if no other handlers present. The consuming app may add other handlers to 'lib' logger or its children.
log = logging.getLogger('lib.{}'.format(__name__))
log.addHandler(logging.NullHandler())


class Config:
    def __init__(self, path, section="config"):
        if not os.path.isfile(path):
            raise IOError("Could not find config file {}".format(path))
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

    def _getfile(self, opt):
        try:
            filename = self._get(opt)
            if filename and os.path.isfile(filename):
                return filename
            else:
                self._configexit("Could not find the file {} = {}".format(opt, filename))
        except NoOptionError, e:
            self._configexit(str(e))
 

    def _configexit(self, msg):
        """Log config error and exit with error code
        """
        log.error("Configuration error in {}: {}".format(self.path, msg))
        print("Configuration error in {}: {}".format(self.path, msg))
        sys.exit(1)






def set_logging(log, loglevel, logfile):
    """Configure standard logging for the application. One ERROR level handler to stderr and one file handler with specified loglevel to logfile.
        log argument is the main (parent) application logger.
    """
    try:
        log.setLevel(loglevel)
        fh = logging.FileHandler(logfile)
        fh.setLevel(loglevel)
        fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)-8s %(filename)s:%(lineno)d.%(funcName)s() - %(message)s'))
        log.addHandler(fh)
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)
        ch.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
        log.addHandler(ch)
        # add log file handler for libraries according to the logging convention
        logging.getLogger('lib').addHandler(fh)    
    except IOError, e:
        print str(e)
        if e.errno == 13:
            print "Problem with writing logs to {}. Do you have sufficient privileges?".format(e.filename)
        elif e.errno == 21:
            print "Problem with writing logs to {}.".format(e.filename)
        sys.exit(1)




