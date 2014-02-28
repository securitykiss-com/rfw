from unittest import TestCase

import cmdparse, cmdexe, timeutil

class CmdParseTest(TestCase):


    def test_parse_command(self):
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

