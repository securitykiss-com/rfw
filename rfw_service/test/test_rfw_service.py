from unittest import TestCase

import cmdparse, cmdexe, timeutil, iptables
from iptables import Rule

class CmdParseTest(TestCase):

    def test_parse_command(self):
        self.assertEqual( 
                cmdparse.parse_command_path('/drop/input/eth0/5.6.7.8'), 
                    ('drop', Rule(chain='INPUT', num=None, pkts=None, bytes=None, target='DROP', prot=None, opt=None, inp='eth0', out='*', source='5.6.7.8', destination='0.0.0.0/0', extra=None)))
        self.assertEqual( 
                cmdparse.parse_command_path('/drop/input/eth /5.6.7.8/'), 
                    ('drop', Rule(chain='INPUT', num=None, pkts=None, bytes=None, target='DROP', prot=None, opt=None, inp='eth+', out='*', source='5.6.7.8', destination='0.0.0.0/0', extra=None)))



    def not_test_parse_command(self):
        self.assertEqual( cmdparse.parse_command('/'), 
                {} )
        self.assertEqual( cmdparse.parse_command("/blabla"), 
                {'error': 'Incorrect chain name'} )
        self.assertEqual( cmdparse.parse_command("/inputer"), 
                {'error': 'Incorrect chain name'} )
        self.assertEqual( cmdparse.parse_command("/input"), 
                {'chain': 'input'} )
        self.assertEqual( cmdparse.parse_command("/input/"), 
                {'chain': 'input'} )
        self.assertEqual( cmdparse.parse_command("/input/11.22.33.44"), 
                {'chain': 'input', 'error': 'Incorrect interface name 1'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44/"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.3333.44/"), 
                {'chain': 'input', 'iface1': 'eth', 'error': 'Incorrect IP address 1'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.4444/"), 
                {'chain': 'input', 'iface1': 'eth', 'error': 'Incorrect IP address 1'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44?expire=3600"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'expire': '3600'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44?expire=20s"),
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'expire': '20'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44?expire=10m"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'expire': '600'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44?expire=2h"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'expire': '7200'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44?expire=2d"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'expire': '172800'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44/?expire=3600&wait=true"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'expire': '3600', 'wait': 'true'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44/ppp"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44'} )
        self.assertEqual( cmdparse.parse_command("/forward/eth/11.22.33.44/ppp"), 
                {'chain': 'forward', 'iface1': 'eth', 'ip1': '11.22.33.44', 'iface2': 'ppp'} )
        self.assertEqual( cmdparse.parse_command("/forward/eth/11.22.33.44/ppp12/"), 
                {'chain': 'forward', 'iface1': 'eth', 'ip1': '11.22.33.44', 'iface2': 'ppp12'} )
        self.assertEqual( cmdparse.parse_command("/forward/eth/11.22.33.44/ppp12/55.66.77.88"), 
                {'chain': 'forward', 'iface1': 'eth', 'ip1': '11.22.33.44', 'iface2': 'ppp12', 'ip2': '55.66.77.88'} )



class CmdExeTest(TestCase):

    def test_iptables_construct(self):
        self.assertEqual( cmdexe.iptables_construct('I', {'action': 'DROP', 'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'expire': '3600'}), 
                ['iptables', '-I', 'INPUT', '-i', 'eth+', '-s', '11.22.33.44', '-j', 'DROP'] )
        self.assertEqual( cmdexe.iptables_construct('I', {'action': 'ACCEPT', 'chain': 'output', 'iface1': 'eth0', 'ip1': '11.22.33.44', 'expire': '3600'}), 
                ['iptables', '-I', 'OUTPUT', '-o', 'eth0', '-d', '11.22.33.44', '-j', 'ACCEPT'] )
        self.assertEqual( cmdexe.iptables_construct('I', {'action': 'DROP', 'chain': 'input', 'iface1': 'any', 'ip1': '11.22.33.44', 'expire': '3600'}), 
                ['iptables', '-I', 'INPUT', '-s', '11.22.33.44', '-j', 'DROP'] )
        self.assertEqual( cmdexe.iptables_construct('D', {'action': 'ACCEPT', 'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'expire': '3600'}), 
                ['iptables', '-D', 'FORWARD', '-i', 'ppp+', '-s', '11.22.33.44', '-j', 'ACCEPT'] )
        self.assertEqual( cmdexe.iptables_construct('I', {'action': 'DROP', 'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'iface2': 'eth0', 'expire': '3600'}), 
                ['iptables', '-I', 'FORWARD', '-i', 'ppp+', '-s', '11.22.33.44', '-o', 'eth0', '-j', 'DROP'] )
        self.assertEqual( cmdexe.iptables_construct('I', {'action': 'DROP', 'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'ip2': '5.6.7.8', 'expire': '3600'}), 
                ['iptables', '-I', 'FORWARD', '-i', 'ppp+', '-s', '11.22.33.44', '-d', '5.6.7.8', '-j', 'DROP'] )
        self.assertEqual( cmdexe.iptables_construct('I', {'action': 'DROP', 'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'iface2': 'eth0', 'ip2': '5.6.7.8', 'expire': '3600'}), 
                ['iptables', '-I', 'FORWARD', '-i', 'ppp+', '-s', '11.22.33.44', '-o', 'eth0', '-d', '5.6.7.8', '-j', 'DROP'] )

#TODO extract reusable libraries along with testcases
class TimeUtilTest(TestCase):
    
    def test_parse_interval(self):
        self.assertEqual( timeutil.parse_interval('350'), 350 )
        self.assertEqual( timeutil.parse_interval('20000s'), 20000 )
        self.assertEqual( timeutil.parse_interval('10m'), 600 )
        self.assertEqual( timeutil.parse_interval('2h'), 7200 )
        self.assertEqual( timeutil.parse_interval('10d'), 864000 )
        self.assertEqual( timeutil.parse_interval('0'), 0 )
        self.assertEqual( timeutil.parse_interval('0m'), 0 )
        self.assertEqual( timeutil.parse_interval('-3'), None )
        self.assertEqual( timeutil.parse_interval('10u'), None )
        self.assertEqual( timeutil.parse_interval('abc'), None )
        self.assertEqual( timeutil.parse_interval(''), None )


class IptablesTest(TestCase):

    def not_test_find(self):

        # this function must be called 'load' to be able to instantiate mock Iptables
        def load(rules):
            inst = iptables.Iptables(rules)
            return inst

        r1 = {'opt': '--', 'destination': '0.0.0.0/0', 'target': 'DROP', 'chain': 'INPUT', 'extra': '', 'prot': 'all', 'bytes': '0', 'source': '2.2.2.2', 'num': '9', 'in': 'eth+', 'pkts': '0', 'out': '*'}
        r2 = {'opt': '--', 'destination': '0.0.0.0/0', 'target': 'ACCEPT', 'chain': 'INPUT', 'extra': 'tcp spt:12345', 'prot': 'tcp', 'bytes': '0', 'source': '3.4.5.6', 'num': '10', 'in': '*', 'pkts': '0', 'out': '*'}
        r3 = {'opt': '--', 'destination': '0.0.0.0/0', 'target': 'DROP', 'chain': 'INPUT', 'extra': 'tcp dpt:7393', 'prot': 'tcp', 'bytes': '840', 'source': '0.0.0.0/0', 'num': '1', 'in': '*', 'pkts': '14', 'out': '*'}
        r4 = {'opt': '--', 'destination': '7.7.7.6', 'target': 'DROP', 'chain': 'OUTPUT', 'extra': '', 'prot': 'all', 'bytes': '0', 'source': '0.0.0.0/0', 'num': '1', 'in': '*', 'pkts': '0', 'out': 'tun+'}

        rules = [r1, r2, r3, r4]
        inst1 = load(rules)
        self.assertEqual( inst1.find({}), rules)
        self.assertEqual( inst1.find({'destination': ['0.0.0.0/0']}), [r1, r2, r3])
        self.assertEqual( inst1.find({'target': ['ACCEPT']}), [r2])
        self.assertEqual( inst1.find({'chain': ['OUTPUT']}), [r4])
        self.assertEqual( inst1.find({'chain': ['OUTPUT'], 'target':['ACCEPT']}), [])
        self.assertEqual( inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target':['ACCEPT']}), [r2])
        self.assertEqual( inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target':['ACCEPT', 'DROP']}), rules)
        self.assertEqual( inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target':['DROP'], 'extra': ['']}), [r1, r4])
        


