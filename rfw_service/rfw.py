from __future__ import print_function
import argparse, logging, re, sys, struct, socket, subprocess, signal, time
from Queue import Queue, PriorityQueue
from threading import Thread
import config, rfwconfig, cmdparse, cmdexe, iputil, rfwthreads
from sslserver import SSLServer, BasicAuthRequestHandler

   
log = logging.getLogger('rfw')

def perr(msg):
    print(msg, file=sys.stderr)


def create_requesthandler(rfwconf, cmd_queue, expiry_queue):
    """Create RequestHandler type. This is a way to avoid global variables: a closure returning a class type that binds rfwconf and cmd_queue inside. 
    """
    class RequestHandler(BasicAuthRequestHandler):
    
        def creds_check(self, user, password):
            return user == rfwconf.auth_username() and password == rfwconf.auth_password()
    
        def http_resp(self, code, content):
            content = str(content)
            self.send_response(code)
            self.send_header("Content-Length", len(content) + 2)
            self.end_headers()
            self.wfile.write(content + "\r\n")
            return
 

        def add_command(self, modify):
            # modify should be 'D' for Delete or 'I' for Insert understood as -D and -I iptables flags
            assert modify == 'D' or modify == 'I'
            log.debug('self.path: {}'.format(self.path))
            
            # parse_command does not raise errors. Errors returned in response
            rcmd = cmdparse.parse_command(self.path)

            log.debug('Parsed command: {}'.format(rcmd))
            
            error = rcmd.get('error')
            if error:
                return self.http_resp(400, error) # Bad Request
            
            chain = rcmd['chain']
            if chain == 'input':
                action = rfwconf.chain_input_action()
            elif chain == 'output':
                action = rfwconf.chain_output_action()
            elif chain == 'forward':
                action = rfwconf.chain_forward_action()
            else:
                assert False, "Wrong chain name: {}".format(chain)
                        
            assert action in ['DROP', 'ACCEPT']

            rcmd['action'] = action
            ctup = (modify, rcmd)
            log.debug('Final command tuple: {}'.format(str(ctup)))

            whitelist = rfwconf.whitelist()           

            # eliminate ignored IP related commands early to prevent propagating them to expiry queue
            ip1 = rcmd['ip1']
            if iputil.in_iplist(ip1, whitelist):
                log.warn("Request {} related to whitelisted IP address {} ignored.".format(str(rcmd), ip))
                # It's more secure to return the same HTTP OK response even if the command is not executed. Don't give attacker extra info.
                return self.http_resp(200, ctup)
            
            if chain == 'forward':
                ip2 = rcmd.get('ip2')
                if ip2 and iputil.in_iplist(ip2, whitelist):
                    log.warn("Request {} related to whitelisted IP address {} ignored.".format(str(rcmd), ip))
                    # It's more secure to return the same HTTP OK response even if the command is not executed. Don't give attacker extra info.
                    return self.http_resp(200, ctup)
 
            cmd_queue.put_nowait(ctup)
            return self.http_resp(200, ctup)
            
    
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
    LOG_LEVEL = 'WARN'
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


def startup_sanity_check(rfwconf):
    """Check for most common errors to give informative message to the user
    """
    ipt = rfwconf.iptables_path()
    # checking if iptables installed
    try:
        cmdexe.call([ipt, '-h'])
    except OSError, e:
        log.critical("Could not find {}. Check if it is correctly installed.".format(ipt))
        sys.exit(1)

    # checking if root - iptables installed but cannot list rules
    try:
        cmdexe.call([ipt, '-n', '-L', 'OUTPUT'])
    except subprocess.CalledProcessError, e:
        log.critical("No access to iptables. The program requires root privileges.")
        sys.exit(1)

    #TODO check if iptables is not pointing to rfwc



def __sigTERMhandler(signum, frame):
    log.debug("Caught signal {}. Exiting".format(signum))
    perr('')
    stop()

def stop():
    logging.shutdown()
    sys.exit(1)



def main():

    args = parse_args()
    config.set_logging(log, args.loglevelnum, args.logfile, args.v)

    if args.v:
        log.info('Console logging in verbose mode')

    try:
        rfwconf = rfwconfig.RfwConfig(args.configfile)
    except IOError, e:
        perr(e.message)
        create_args_parser().print_usage()
        sys.exit(1)

    startup_sanity_check(rfwconf)

    
    log.info("Starting rfw server")
    log.info("Whitelisted IP addresses that will be ignored:")
    for a in rfwconf.whitelist():
        log.info(a)


    # Install signal handlers
    signal.signal(signal.SIGTERM, __sigTERMhandler)
    signal.signal(signal.SIGINT, __sigTERMhandler)
    # TODO we may also need to ignore signal.SIGHUP in daemon mode


    rules = cmdexe.iptables_list()
    rcmds = cmdexe.rules_to_rcmds(rules)

    # TODO make logging more efficient by deferring arguments evaluation
    log.debug("===== rules =====\n{}".format("\n".join(map(str, rules))))
    log.debug("===== rcmds =====\n{}".format("\n".join(map(str, rcmds))))


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
