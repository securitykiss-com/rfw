import argparse, logging, re, sys
from Queue import Queue
from threading import Thread
import config, cmdparse, cmdexe
from sslserver import SSLServer, BasicAuthRequestHandler

   




def create_requesthandler(rfwconf, cmd_queue):
    """Create RequestHandler type. This is a way to avoid global variables: a closure returning a class type that binds rfwconf inside. 
    """
    class RequestHandler(BasicAuthRequestHandler):
    
        def creds_check(self, user, password):
            return user == rfwconf.auth_username() and password == rfwconf.auth_password()
    
        
        # modify should be 'D' for Delete or 'I' for Insert understood as -D and -I iptables flags
        def add_command(self, modify):
            assert modify == 'D' or modify == 'I'
            print("self.path=" + self.path)
            
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
            rcmd['modify'] = modify
            
            print("command2: %s" % rcmd) 

            cmd_queue.put_nowait(rcmd)

            content = str(rcmd)
    
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
                #TODO here it will be more complicated. The GET listing requests are valid in restful scenario
                self.do_POST()
            else:
                self.send_response(405) # Method Not Allowed
    
        def do_POST(self):
            self.add_command('I')

    return RequestHandler



def parse_commandline():
    parser = argparse.ArgumentParser(description='rfw - Remote Firewall')
    parser.add_argument('-f', '--configfile', default='/etc/rfw/rfw.conf', help='rfw config file')
    args = parser.parse_args()
    return args.configfile


def process_commands(cmd_queue, whitelist):
    while True:
        rcmd = cmd_queue.get()
        lcmd = cmdexe.construct_iptables(rcmd)
        #TODO check for duplicates, check the whitelist, execute command
        #TODO for whitelist addresses action/noaction depends on chain.input.action:
        
        
        action = rcmd['action']
        chain = rcmd['chain']

        ip1 = rcmd['ip1']
        
        if ip1 in whitelist:
            #TODO
            pass
        
        if chain == 'forward':
            ip2 = rcmd.get('ip2')
            if ip2 and ip2 in whitelist:
                #TODO
                pass 

        #TODO log warning if ip is from whitelist

        #TODO need to think over the in memory representation of 
        print "Got from Queue:\n{}\n{}".format(rcmd, lcmd)
        cmd_queue.task_done()



def main():
    configfile = parse_commandline()
    #TODO check for 'config' name collision
    #config = load_config(configfile)

    rfwconf = config.RfwConfig("rfw.conf")

    #TODO replace with bind address and port from config
    server_address = ('localhost', 8443) # (address, port)


    cmd_queue = Queue()
    consumer = Thread(target=process_commands, args=(cmd_queue, rfwconf.whitelist()))
    consumer.setDaemon(True)
    consumer.start()

    #passing HandlerClass to SSLServer is very limiting, seems like a bad design of BaseServer. In order to pass extra info to eequestHandler without using global variable we have to wrap the class in closure
    HandlerClass = create_requesthandler(rfwconf, cmd_queue)
    httpd = SSLServer(server_address, HandlerClass, rfwconf.outward_server_certfile(), rfwconf.outward_server_keyfile())

    sa = httpd.socket.getsockname()
    print "Serving HTTPS on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


if __name__ == "__main__":
    main()
