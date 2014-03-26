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
from threading import Thread
import time, logging
import iputil, iptables
from iptables import Iptables

log = logging.getLogger('rfw.rfwthreads')


class CommandProcessor(Thread):

    def __init__(self, cmd_queue, whitelist, expiry_queue, default_expire):
        Thread.__init__(self)
        self.cmd_queue = cmd_queue
        self.whitelist = whitelist
        self.expiry_queue = expiry_queue
        self.default_expire = default_expire
        self.setDaemon(True)


    def schedule_expiry(self, rule, directives):
        # put time-bounded command to the expiry_queue
        expire = directives.get('expire', self.default_expire)
        assert isinstance(expire, str) and expire.isdigit()
        # expire='0' means permanent rule which is not added to the expiry queue
        if int(expire):
            expiry_tstamp = time.time() + int(expire)
            extup = (expiry_tstamp, expire, rule)
            self.expiry_queue.put_nowait(extup)
            log.debug('PUT to Expiry Queue. expiry_queue: {}'.format(self.expiry_queue.queue))


    def run(self):
        ruleset = set(Iptables.read_simple_rules())
        while True:
            modify, rule, directives = self.cmd_queue.get()
            try:
                rule_exists = rule in ruleset
                log.debug('{} rule_exists: {}'.format(rule, rule_exists))
 
                # check for duplicates, apply rule
                if modify == 'I':
                    if rule_exists:
                        log.warn("Trying to insert existing rule: {}. Command ignored.".format(rule))
                    else:
                        Iptables.exe_rule(modify, rule)
                        # schedule expiry timeout if present. Only for Insert rules and only if the rule didn't exist before (so it was added now)
                        self.schedule_expiry(rule, directives)
                        ruleset.add(rule)
                elif modify == 'D':
                    if rule_exists:
                        #TODO delete rules in the loop to delete actual iptables duplicates. It's to satisfy idempotency and plays well with common sense
                        Iptables.exe_rule(modify, rule)
                        ruleset.discard(rule)
                    else:
                        log.warn("Trying to delete not existing rule: {}. Command ignored.".format(rule))
                elif modify == 'L':
                    #TODO rereading the iptables?
                    pass
            finally:    
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
        # Not thread safe! It's OK here because we have single producer and single consumer, where consumer need not atomic 'peek and get'
        def peek(q):
            if q.queue:
                return q.queue[0]
            else:
                return None

        while True:
            time.sleep(ExpiryManager.POLL_INTERVAL)

            # Move expired items from expiry_queue to cmd_queue for deletion
            item = peek(self.expiry_queue)
            if item is None:
                continue
            expiry_tstamp, expire, rule = item
            # skip if the next candidate expires in the future
            if expiry_tstamp > time.time():
                continue
            try:
                # get item with lowest priority score. It may be different (but certainly lower) from the one returned by peek() since peek() is not thread safe
                expiry_tstamp, expire, rule = self.expiry_queue.get()
                log.debug('GET from Expiry Queue. expiry_queue: {}'.format(self.expiry_queue.queue))
                # expire parameter is valid only for 'I' (insert) commands, so expiring the rule is as simple as deleting it
                directives = {}
                tup = ('D', rule, directives)
                self.cmd_queue.put_nowait(tup)
            finally:
                self.expiry_queue.task_done()


            
class ServerRunner(Thread):

    def __init__(self, httpd):
        Thread.__init__(self)
        self.httpd = httpd
        self.setDaemon(True)

    def run(self):
        sa = self.httpd.socket.getsockname()
        log.info("Serving HTTP on {} port {}".format(sa[0], sa[1]))
        self.httpd.serve_forever()
        







