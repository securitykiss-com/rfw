from __future__ import print_function
from threading import Thread
import time, logging
import cmdexe, iputil

log = logging.getLogger('rfw.rfwthreads')


class CommandProcessor(Thread):

    def __init__(self, cmd_queue, whitelist):
        Thread.__init__(self)
        self.cmd_queue = cmd_queue
        self.whitelist = whitelist
        self.setDaemon(True)

    def is_ip_ignored(self, ip, whitelist, modify, rcmd):
        """Prevent adding DROP rules and prevent deleting ACCEPT rules for whitelisted IPs.
        Also log the such attempts as warnings.
        """
        action = rcmd['action']
        if iputil.in_iplist(ip, self.whitelist):
            if (modify == 'I' and action == 'DROP') or (modify == 'D' and action == 'ACCEPT'):
                log.warn("Request {} related to whitelisted IP address {} ignored.".format(str(rcmd), ip))
                return True
        return False
 
    def apply_rule(self, modify, rcmd):
        lcmd = cmdexe.iptables_construct(modify, rcmd)
        out = cmdexe.call(lcmd)
        if out:
            log.warn("Non empty output from the command: {}. The output: '{}'".format(lcmd, out))
        return out


    def run(self):
        #TODO iptables_list() here  and store in local var?
        rules = cmdexe.iptables_list()
        rcmds = cmdexe.rules_to_rcmds(rules)
    
        #TODO make sure if the rcmds format from iptables_list()/rules_to_rcmds() conforms to REST rcmds from cmdparse 
        #TODO add consistency checks
    
        while True:
            # read (modify, rcmd) tuple from the queue
            modify, rcmd = self.cmd_queue.get()
            
            print("Got from Queue:\n{}".format(rcmd))
    
            rule_exists = rcmd in rcmds
    
    
            action = rcmd['action']
            chain = rcmd['chain']
    
            ip1 = rcmd['ip1']
            if self.is_ip_ignored(ip1, self.whitelist, modify, rcmd): 
                self.cmd_queue.task_done()
                continue
            
            if chain == 'forward':
                ip2 = rcmd.get('ip2')
                if self.is_ip_ignored(ip2, self.whitelist, modify, rcmd):
                    self.cmd_queue.task_done()
                    continue
    
    
            # check for duplicates, apply rule
            #TODO compare with memory model, make it robust, reread the model with iptables_list() if necessary (append 'L' rcmd to the queue, so it will be applied in the next loop iteration) 
            if modify == 'I':
                if rule_exists:
                    log.warn("Trying to insert existing rule: {}. Command ignored.".format(rcmd))
                else:
                    self.apply_rule(modify, rcmd)
                    log.info("Inserting the rule: {}".format(rcmd))
            elif modify == 'D':
                if rule_exists:
                    self.apply_rule(modify, rcmd)
                    log.info("Deleting the rule: {}".format(rcmd))
                else:
                    log.warn("Trying to delete not existing rule: {}. Command ignored.".format(rcmd))
            elif modify == 'L':
                #TODO rereading the iptables?
                pass
    
            #TODO put it in finally block
            self.cmd_queue.task_done()






class ExpiryManager(Thread):
    
    # polling interval in seconds that determines time resolution of expire parameter
    POLL_INTERVAL = 5


    def __init__(self, cmd_queue, expiry_queue):
        """cmd_queue is a FIFO queue of (modify, rcmd) tuples
        expiry_queue is a priority queue of (expiry_tstamp, rcmd) tuples
        """
        Thread.__init__(self)
        self.cmd_queue = cmd_queue
        self.expiry_queue = expiry_queue
        self.setDaemon(True)

    def run(self):
        while True:
            #TODO move expired items from expiry_queue to cmd_queue
            #TODO check for duplicates in priority queue?

            log.error('Next step of expiry manager')
            time.sleep(ExpiryManager.POLL_INTERVAL)
            






