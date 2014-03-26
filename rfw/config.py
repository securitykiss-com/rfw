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

from __future__ import print_function
import logging, sys, types, os.path, re
from ConfigParser import RawConfigParser, NoOptionError

# Follow the logging convention:
# - Modules intended as reusable libraries have names 'lib.<modulename>' what allows to configure single parent 'lib' logger for all libraries in the consuming application
# - Add NullHandler (since Python 2.7) to prevent error message if no other handlers present. The consuming app may add other handlers to 'lib' logger or its children.
log = logging.getLogger('lib.{}'.format(__name__))
log.addHandler(logging.NullHandler())

class ConfigError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


class Config:
    def __init__(self, path, section="config"):
        self.path = path
        self.section = section
        if not os.path.isfile(path):
            raise IOError("Could not find config file {}".format(path))
        self.parser = RawConfigParser(allow_no_value=True)
        self.parser.read(self.path)

    # throws NoOptionError
    def _get(self, opt):
        """Get option value from [config] section of config file.
        It may return None if valueless option present (option name only). It's possible because allow_no_value=True
        It may raise NoOptionError if option not present
        It may raise NoSectionError
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

    # throws NoOptionError or ConfigError
    def _getfile(self, opt):
        filename = self._get(opt)
        if filename and os.path.isfile(filename):
            return filename
        else:
            raise self.config_error("Could not find the file {} = {}".format(opt, filename))
 
    # create ConfigError
    def config_error(self, msg):
        return ConfigError('Configuration error in {}: {}'.format(self.path, msg))




def set_logging(log, loglevelnum, logfile, verbose_console=False):
    """Configure standard logging for the application. One ERROR level handler to stderr and one file handler with specified loglevelnum to logfile.
        log argument is the main (parent) application logger.
    """
    # Prevent common error in using this API: loglevelnum is numeric
    if not loglevelnum in [logging.NOTSET, logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL]:
        log.error("Incorrect loglevel value")
        sys.exit(1)

    try:
        # Specific log levels are set on individual handlers, but we must also set the most permissive log level on the logger itself to pass the initial filter.
        log.setLevel(logging.DEBUG)
        fh = logging.FileHandler(logfile)
        fh.setLevel(loglevelnum)
        fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)-8s %(filename)s:%(lineno)d.%(funcName)s() - %(message)s'))
        log.addHandler(fh)
        ch = logging.StreamHandler()
        if verbose_console:
            ch.setLevel(logging.DEBUG)
        else:
            ch.setLevel(logging.ERROR)
        ch.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
        log.addHandler(ch)
        # add log file handler for libraries according to the logging convention
        logging.getLogger('lib').addHandler(fh)    
    except IOError, e:
        msg = str(e)
        if e.errno == 13:
            msg += '\nYou need to be root'
        raise ConfigError(msg)




