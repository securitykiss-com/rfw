from __future__ import print_function
import argparse, logging, re, sys, struct, socket, subprocess, signal, time, json
from Queue import Queue, PriorityQueue
from threading import Thread
import config, rfwconfig, cmdparse, iputil, rfwthreads, iptables
from sslserver import SSLServer, BasicAuthRequestHandler
from iptables import Iptables

   
log = logging.getLogger('rfw')

def perr(msg):
    print(msg, file=sys.stderr)


def create_requesthandler(rfwconf, cmd_queue, expiry_queue):
    """Create RequestHandler type. This is a way to avoid global variables: a closure returning a class type that binds rfwconf and cmd_queue inside. 
    """
    class RequestHandler(BasicAuthRequestHandler):
        
        # override to include access logs in main log file
        def log_message(self, format, *args):
            log.info("%s - - [%s] %s" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          format%args))

        def creds_check(self, user, password):
            return user == rfwconf.auth_username() and password == rfwconf.auth_password()
    
        def http_resp(self, code, content):
            content = str(content)
            self.send_response(code)
            self.send_header("Content-Length", len(content) + 2)
            self.end_headers()
            self.wfile.write(content + "\r\n")
            return

        def check_whitelist_conflict(self, whitelist, ip):
            if ip != '0.0.0.0/0' and iputil.ip_in_list(ip, whitelist):
                msg = 'Ignoring the request conflicting with the whitelist'
                log.warn(msg)
                raise Exception(msg)


        def add_command(self, modify):
            # modify should be 'D' for Delete or 'I' for Insert understood as -D and -I iptables flags
            assert modify == 'D' or modify == 'I'
            log.debug('self.path: {}'.format(self.path))
            whitelist = rfwconf.whitelist()
            
            # authenticate by checking if client IP is in the whitelist - normally reqests from non-whitelisted IPs should be blocked by firewall before
            client_ip = self.client_address[0]
            if not iputil.ip_in_list(client_ip, whitelist):
                log.error('Request from client IP: {} which is not authorized in the whitelist. It should have been blocked by firewall.'.format(client_ip))
                return self.http_resp(403, '') # Forbidden 
 
            try:
                action, rule, directives = cmdparse.parse_command(self.path)
                log.debug('\nAction: {}\nRule: {}\nDirectives: {}'.format(action, rule, directives))
                if action == 'list':
                    chain = rule
                    rules = Iptables.read_simple_rules(chain)
                    log.debug('List rfw rules: %s', rules) 
                    list_of_dict = map(iptables.Rule._asdict, rules)                    
                    resp = json.dumps(list_of_dict)
                    return self.http_resp(200, resp)
                elif action.upper() in iptables.RULE_TARGETS:
                    # eliminate ignored/whitelisted IP related commands early to prevent propagating them to expiry queue
                    self.check_whitelist_conflict(whitelist, rule.source)
                    self.check_whitelist_conflict(whitelist, rule.destination)
                    ctup = (modify, rule, directives)
                    log.debug('PUT to Cmd Queue. Tuple: {}'.format(ctup))
                    cmd_queue.put_nowait(ctup)
                    return self.http_resp(200, ctup)
                else:
                    raise Exception('Unrecognized action: {}'.format(action))
            except Exception, e:
                msg = 'add_command error: {}'.format(e.message)
                # logging as error disabled - bad client request is not an error 
                # log.exception(msg)
                log.info(msg)
                return self.http_resp(400, msg) # Bad Request
            
    
        def do_PUT(self):
            self.add_command('I')
    
        def do_DELETE(self):
            self.add_command('D')
    
        def do_GET(self):
            if rfwconf.is_non_restful(): 
                #TODO here it will be more complicated. The GET requests are valid in restful scenario for listing rfw status
                self.do_POST()
            else:
                self.send_response(405) # Method Not Allowed
    
        def do_POST(self):
            self.add_command('I')

    return RequestHandler





def create_args_parser():
    CONFIG_FILE = '/etc/rfw/rfw.conf'
    # TODO change default log level to INFO
    LOG_LEVEL = 'DEBUG'
    LOG_FILE = '/var/log/rfw.log'
    parser = argparse.ArgumentParser(description='rfw - Remote Firewall')
    parser.add_argument('-f', default=CONFIG_FILE, metavar='CONFIGFILE', dest='configfile', help='rfw config file (default {})'.format(CONFIG_FILE))
    parser.add_argument('--loglevel', default=LOG_LEVEL, help='Log level (default {})'.format(LOG_LEVEL), choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('--logfile', default=LOG_FILE, help='Log file (default {})'.format(LOG_FILE))
    parser.add_argument('-v', help='Verbose console output. Sets DEBUG log level for stderr logger (default ERROR)', action='store_true')
    return parser

def parse_args():
    parser = create_args_parser()
    args = parser.parse_args()
    args.loglevelnum = getattr(logging, args.loglevel)
    return args


def startup_sanity_check():
    """Check for most common errors to give informative message to the user
    """
    try:
        Iptables.verify_install()
        Iptables.verify_permission()
        Iptables.verify_original()
    except Exception, e:
        log.critical(e)
        sys.exit(1)


def __sigTERMhandler(signum, frame):
    log.debug("Caught signal {}. Exiting".format(signum))
    perr('')
    stop()

def stop():
    logging.shutdown()
    sys.exit(1)


def rfw_init_rules(rfwconf):
    """Clean and insert the rfw init rules.
    The rules block all INPUT/OUTPUT traffic on rfw ssl port except for whitelisted IPs.
    Here are the rules that should be created assuming that that the only whitelisted IP is 127.0.0.1:
        Rule(chain='INPUT', num='1', pkts='0', bytes='0', target='ACCEPT', prot='tcp', opt='--', inp='*', out='*', source='127.0.0.1', destination='0.0.0.0/0', extra='tcp dpt:7393')
        Rule(chain='INPUT', num='4', pkts='0', bytes='0', target='DROP', prot='tcp', opt='--', inp='*', out='*', source='0.0.0.0/0', destination='0.0.0.0/0', extra='tcp dpt:7393')
        Rule(chain='OUTPUT', num='1', pkts='0', bytes='0', target='ACCEPT', prot='tcp', opt='--', inp='*', out='*', source='0.0.0.0/0', destination='127.0.0.1', extra='tcp spt:7393')
        Rule(chain='OUTPUT', num='4', pkts='0', bytes='0', target='DROP', prot='tcp', opt='--', inp='*', out='*', source='0.0.0.0/0', destination='0.0.0.0/0', extra='tcp spt:7393')
    """
    rfw_port = rfwconf.outward_server_port()
    ipt = Iptables.load()

    ###
    log.info('Delete existing init rules')
    # find 'drop all packets to and from rfw port'
    drop_input = ipt.find({'target': ['DROP'], 'chain': ['INPUT'], 'prot': ['tcp'], 'extra': ['tcp dpt:' + rfw_port]})
    log.info(drop_input)
    log.info('Existing drop input to rfw port {} rules:\n{}'.format(rfw_port, '\n'.join(map(str, drop_input))))
    for r in drop_input:
        Iptables.exe_rule('D', r)
    drop_output = ipt.find({'target': ['DROP'], 'chain': ['OUTPUT'], 'prot': ['tcp'], 'extra': ['tcp spt:' + rfw_port]})
    log.info('Existing drop output to rfw port {} rules:\n{}'.format(rfw_port, '\n'.join(map(str, drop_output))))
    for r in drop_output:
        Iptables.exe_rule('D', r)

    ###
    log.info('Insert DROP rfw port init rules')
    Iptables.exe(['-I', 'INPUT', '-p', 'tcp', '--dport', rfw_port, '-j', 'DROP'])
    Iptables.exe(['-I', 'OUTPUT', '-p', 'tcp', '--sport', rfw_port, '-j', 'DROP'])

    ###
    log.info('Insert ACCEPT whitelist IP rfw port init rules')
    for ip in rfwconf.whitelist():
        Iptables.exe(['-I', 'INPUT', '-p', 'tcp', '--dport', rfw_port, '-s', ip, '-j', 'ACCEPT'])
        Iptables.exe(['-I', 'OUTPUT', '-p', 'tcp', '--sport', rfw_port, '-d', ip, '-j', 'ACCEPT'])


def main():

    args = parse_args()
    try:
        config.set_logging(log, args.loglevelnum, args.logfile, args.v)
    except config.ConfigError, e:
        perr(e.message)
        sys.exit(1)

    if args.v:
        log.info('Console logging in verbose mode')
    
    log.info("Logging to file: {}".format(args.logfile))
    log.info("File log level: {}".format(args.loglevel))

    try:
        rfwconf = rfwconfig.RfwConfig(args.configfile)
    except IOError, e:
        perr(e.message)
        create_args_parser().print_usage()
        sys.exit(1)

    # Initialize Iptables with configured path to system iptables 
    Iptables.ipt_path = rfwconf.iptables_path()
    startup_sanity_check()

    # Install signal handlers
    signal.signal(signal.SIGTERM, __sigTERMhandler)
    signal.signal(signal.SIGINT, __sigTERMhandler)
    # TODO we may also need to ignore signal.SIGHUP in daemon mode
    


    rules = Iptables.load().rules
    # TODO make logging more efficient by deferring arguments evaluation
    log.debug("===== rules =====\n{}".format("\n".join(map(str, rules))))

    log.info("Starting rfw server")
    log.info("Whitelisted IP addresses that will be ignored:")
    for a in rfwconf.whitelist():
        log.info('    {}'.format(a))

    # recreate rfw init rules related to rfw port
    rfw_init_rules(rfwconf)

    expiry_queue = PriorityQueue()
    cmd_queue = Queue()

    rfwthreads.CommandProcessor(cmd_queue, 
                                rfwconf.whitelist(),
                                expiry_queue,
                                rfwconf.default_expire()).start()

    rfwthreads.ExpiryManager(cmd_queue, expiry_queue).start()

    # Passing HandlerClass to SSLServer is very limiting, seems like a bad design of BaseServer. 
    # In order to pass extra info to RequestHandler without using global variable we have to wrap the class in closure.
    HandlerClass = create_requesthandler(rfwconf, cmd_queue, expiry_queue)
    if rfwconf.is_outward_server():
        server_address = (rfwconf.outward_server_ip(), int(rfwconf.outward_server_port()))
        httpd = SSLServer(
                    server_address, 
                    HandlerClass, 
                    rfwconf.outward_server_certfile(), 
                    rfwconf.outward_server_keyfile())
        sa = httpd.socket.getsockname()
        log.info("Serving HTTPS on {} port {}".format(sa[0], sa[1]))
        httpd.serve_forever()

    assert False, "There should be at least one non-daemon"

if __name__ == "__main__":
    main()
