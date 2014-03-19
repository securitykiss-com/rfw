import subprocess, logging, re

log = logging.getLogger("rfw.log")

def call(lcmd):
    try:
        log.debug('Call: {}'.format(' '.join(lcmd)))
        out = subprocess.check_output(lcmd, stderr=subprocess.STDOUT)
        if out: 
            log.debug("Call output: {}".format(out))
        return out
    except subprocess.CalledProcessError, e:
        log.error("Error code {} returned when called '{}'. Command output: '{}'".format(e.returncode, e.cmd, e.output))
        raise e





