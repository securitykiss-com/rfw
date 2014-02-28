from __future__ import print_function
import argparse, logging, re, sys, struct, socket, subprocess, signal
from Queue import Queue
from threading import Thread
import config, rfwconfig, cmdparse, cmdexe, iputil
from sslserver import SSLServer, BasicAuthRequestHandler

   
log = logging.getLogger('rfw')

def perr(msg):
    print(msg, file=sys.stderr)


def create_requesthandler(rfwconf, cmd_queue):
    """Create RequestHandler type. This is a way to avoid global variables: a closure returning a class type that binds rfwconf and cmd_queue inside. 
    """
    class RequestHandler(BasicAuthRequestHandler):
    
        def creds_check(self, user, password):
            return user == rfwconf.auth_username() and password == rfwconf.auth_password()
    
        
        # modify should be 'D' for Delete or 'I' for Insert understood as -D and -I iptables flags
        def add_command(self, modify):
            assert modify == 'D' or modify == 'I'
            print("self.path=" + self.path)
            
            #TODO add error raising in parse_command and handle it here
            rcmd = cmdparse.parse_command(self.path)

            print("command1: %s" % rcmd) 
            if rcmd.get('error'):
                content = rcmd['error']
                self.send_response(400)  # Bad Request
                self.send_header("Content-Length", len(content) + 2)
                self.end_headers()
                self.wfile.write(content + "\r\n")
                return
                
            
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
            

            tup = (modify, rcmd)
            print("command2 tup: %s" % str(tup))

            
            cmd_queue.put_nowait(tup)

            content = str(tup)
    
            #request content can be read from rfile
            #inp = self.rfile.read(65000) # use Content-Length to know how many bytes to read
            #content = inp + "\r\n" + content
    
            self.send_response(200)
            self.send_header("Content-Length", len(content) + 2)
            self.send_header("Last-Modified", self.date_time_string())
            self.end_headers()
            self.wfile.write(content + "\r\n")

            
    
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
    parser.add_argument('-v', help='The same as \'--loglevel DEBUG\'', action='store_true')
    return parser

def parse_args():
    parser = create_args_parser()
    args = parser.parse_args()
    if args.v:
        args.loglevel = 'DEBUG'
    # TODO
    args.loglevelnum = getattr(logging, args.loglevel)
    return args


def process_commands(cmd_queue, whitelist):
    def is_ip_ignored(ip, whitelist, modify, rcmd):
        """Prevent adding DROP rules and prevent deleting ACCEPT rules for whitelisted IPs.
        Also log the such attempts as warnings.
        """
        action = rcmd['action']
        if iputil.in_iplist(ip, whitelist):
            if (modify == 'I' and action == 'DROP') or (modify == 'D' and action == 'ACCEPT'):
                log.warn("Request {} related to whitelisted IP address {} ignored.".format(str(rcmd), ip))
                return True
        return False
 
    def apply_rule(modify, rcmd):
        lcmd = cmdexe.iptables_construct(modify, rcmd)
        out = cmdexe.call(lcmd)
        if out:
            log.warn("Non empty output from the command: {}. The output: '{}'".format(lcmd, out))
        return out


    #TODO iptables_list() here  and store in local var?
    rules = cmdexe.iptables_list()
    rcmds = cmdexe.rules_to_rcmds(rules)

    #TODO make sure if the rcmds format from iptables_list()/rules_to_rcmds() conforms to REST rcmds from cmdparse 
    #TODO add consistency checks

    while True:
        # read (modify, rcmd) tuple from the queue
        modify, rcmd = cmd_queue.get()
        
        print("Got from Queue:\n{}".format(rcmd))

        rule_exists = rcmd in rcmds


        action = rcmd['action']
        chain = rcmd['chain']

        ip1 = rcmd['ip1']
        if is_ip_ignored(ip1, whitelist, modify, rcmd): 
            cmd_queue.task_done()
            continue
        
        if chain == 'forward':
            ip2 = rcmd.get('ip2')
            if is_ip_ignored(ip2, whitelist, modify, rcmd):
                cmd_queue.task_done()
                continue


        # check for duplicates, apply rule
        #TODO compare with memory model, make it robust, reread the model with iptables_list() if necessary (append 'L' rcmd to the queue, so it will be applied in the next loop iteration) 
        if modify == 'I':
            if rule_exists:
                log.warn("Trying to insert existing rule: {}. Command ignored.".format(rcmd))
            else:
                apply_rule(modify, rcmd)
                log.info("Inserting the rule: {}".format(rcmd))
        elif modify == 'D':
            if rule_exists:
                apply_rule(modify, rcmd)
                log.info("Deleting the rule: {}".format(rcmd))
            else:
                log.warn("Trying to delete not existing rule: {}. Command ignored.".format(rcmd))
        elif modify == 'L':
            #TODO rereading the iptables?
            pass

        #TODO put it in finally block
        cmd_queue.task_done()



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
    config.set_logging(log, args.loglevelnum, args.logfile)

    # print(args.loglevelnum, args.logfile, args.configfile)

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

    print("\nrules\n===============\n")
    print("\n".join(map(str, rules)))
    print("\nrcmds\n===============\n")
    print("\n".join(map(str, rcmds)))




    cmd_queue = Queue()
    consumer = Thread(target=process_commands, args=(cmd_queue, rfwconf.whitelist()))
    consumer.setDaemon(True)
    consumer.start()

    # Passing HandlerClass to SSLServer is very limiting, seems like a bad design of BaseServer. 
    # In order to pass extra info to RequestHandler without using global variable we have to wrap the class in closure.
    HandlerClass = create_requesthandler(rfwconf, cmd_queue)
    if rfwconf.is_outward_server():
        server_address = (rfwconf.outward_server_ip(), int(rfwconf.outward_server_port()))
        httpd = SSLServer(
                    server_address, 
                    HandlerClass, 
                    rfwconf.outward_server_certfile(), 
                    rfwconf.outward_server_keyfile())
        sa = httpd.socket.getsockname()
        print("Serving HTTPS on", sa[0], "port", sa[1], "...")
        httpd.serve_forever()

    

    assert False, "There should be at least one non-daemon"

if __name__ == "__main__":
    main()
