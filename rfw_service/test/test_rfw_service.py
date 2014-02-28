import unittest

import cmdparse

class CmdParseTest(unittest.TestCase):


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
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44?timeout=3600"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '3600'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44?timeout=20s"),
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '20'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44?timeout=10m"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '600'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44?timeout=2h"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '7200'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44?timeout=2d"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '172800'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44/?timeout=3600&wait=true"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '3600', 'wait': 'true'} )
        self.assertEqual( cmdparse.parse_command("/input/eth/11.22.33.44/ppp"), 
                {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44'} )
        self.assertEqual( cmdparse.parse_command("/forward/eth/11.22.33.44/ppp"), 
                {'chain': 'forward', 'iface1': 'eth', 'ip1': '11.22.33.44', 'iface2': 'ppp'} )
        self.assertEqual( cmdparse.parse_command("/forward/eth/11.22.33.44/ppp12/"), 
                {'chain': 'forward', 'iface1': 'eth', 'ip1': '11.22.33.44', 'iface2': 'ppp12'} )
        self.assertEqual( cmdparse.parse_command("/forward/eth/11.22.33.44/ppp12/55.66.77.88"), 
                {'chain': 'forward', 'iface1': 'eth', 'ip1': '11.22.33.44', 'iface2': 'ppp12', 'ip2': '55.66.77.88'} )



