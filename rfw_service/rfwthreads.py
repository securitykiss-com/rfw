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
 


    def run(self):
        #TODO iptables_list() here  and store in local var?
        rules = cmdexe.iptables_list()
        # get the set of frozen rcmd
        rcmds = cmdexe.rules_to_rcmds(rules)
    
        #TODO make sure if the rcmds format from iptables_list()/rules_to_rcmds() conforms to REST rcmds from cmdparse 
        #TODO add consistency checks
    
        while True:
            # read (modify, rcmd) tuple from the queue
            modify, rcmd = self.cmd_queue.get()
            # immutable rcmd dict for rcmds set operations
            frozen_rcmd = frozenset(rcmd)

            print("Got from Queue:\n{}".format(rcmd))
    
            rule_exists = frozen_rcmd in rcmds
    
    
            action = rcmd['action']
            chain = rcmd['chain']
    
            #TODO MOVE this check TO RequestHandler, to eliminate ignored IPs early and to prevent propagating them to expiry queue
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
                    cmdexe.apply_rule(modify, rcmd)
                    rcmds.add(frozen_rcmd)
            elif modify == 'D':
                if rule_exists:
                    cmdexe.apply_rule(modify, rcmd)
                    rcmds.discard(frozen_rcmd)
                else:
                    log.warn("Trying to delete not existing rule: {}. Command ignored.".format(rcmd))
            elif modify == 'L':
                #TODO rereading the iptables?
                pass
    
            #TODO put it in finally block
            self.cmd_queue.task_done()






class ExpiryManager(Thread):
    
    # polling interval in seconds that determines time resolution of expire parameter
    POLL_INTERVAL = 1


    def __init__(self, cmd_queue, expiry_queue):
        """cmd_queue is a FIFO queue of (modify, rcmd) tuples
        expiry_queue is a priority queue of (expiry_tstamp, rcmd) tuples
        """
        Thread.__init__(self)
        self.cmd_queue = cmd_queue
        self.expiry_queue = expiry_queue
        self.setDaemon(True)




    
    def run(self):
        # Not thread safe! It's OK here because we have single producer and single consumer
        def peek(q):
            if q.queue:
                return q.queue[0]
            else:
                return None

        while True:
            time.sleep(ExpiryManager.POLL_INTERVAL)


            print(self.expiry_queue.queue)

            # Move expired items from expiry_queue to cmd_queue
            #TODO check for duplicates in priority queue?
            p = peek(self.expiry_queue)
            if p is None:
                continue
            expiry_tstamp, rcmd = p
            # next candidate expires in future so skip
            if expiry_tstamp > time.time():
                continue
            # get item with lowest priority score. It may be different (but certainly lower) from the one returned by peek() since peek() is not thread safe
            expiry_tstamp, rcmd = self.expiry_queue.get()
            # expire parameter is only for PUT commands so expiry_queue should only contain 'I' (insert) commands
            # to expire the rule we delete 'D' the rule
            #TODO make assert when putting to the queue
            tup = ('D', rcmd)
            self.cmd_queue.put_nowait(tup)

            






