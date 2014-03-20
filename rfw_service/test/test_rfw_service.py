from unittest import TestCase

import cmdparse, timeutil, iptables, iputil
from iptables import Rule

class CmdParseTest(TestCase):

    def test_parse_command(self):
        self.assertEqual( 
                cmdparse.parse_command_path('/drop/input/eth0/5.6.7.8'), 
                    ('drop', Rule(chain='INPUT', num=None, pkts=None, bytes=None, target='DROP', prot='all', opt='--', inp='eth0', out='*', source='5.6.7.8', destination='0.0.0.0/0', extra='')))
        self.assertEqual( 
                cmdparse.parse_command_path('/drop/input/eth /5.6.7.8/'), 
                    ('drop', Rule(chain='INPUT', num=None, pkts=None, bytes=None, target='DROP', prot='all', opt='--', inp='eth+', out='*', source='5.6.7.8', destination='0.0.0.0/0', extra='')))



class IpUtilTest(TestCase):

    def test_ip2long(self):
        self.assertEqual(iputil.ip2long('1.2.3.4'), 16909060)
        self.assertEqual(iputil.ip2long('1.2.3.250'), 16909306)
        self.assertEqual(iputil.ip2long('250.2.3.4'), 4194435844)
        self.assertEqual(iputil.ip2long('129.2.3.129'), 2164392833)

    def test_cidr2range(self):
        self.assertEqual(iputil.cidr2range('1.2.3.4'), (16909060, 16909060))
        self.assertEqual(iputil.cidr2range('1.2.3.4/32'), (16909060, 16909060))
        self.assertEqual(iputil.cidr2range('1.2.3.4/31'), (16909060, 16909061))
        self.assertEqual(iputil.cidr2range('1.2.3.4/30'), (16909060, 16909063))
        self.assertEqual(iputil.cidr2range('1.2.3.4/0'), (0, 4294967295))
        self.assertEqual(iputil.cidr2range('129.2.3.129/28'), (2164392832, 2164392847))

    def test_ip_in_list(self):
        self.assertEqual(iputil.ip_in_list('1.2.0.0/16', ['1.2.3.4']), True)



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

    # this function must be called 'load' to be able to instantiate mock Iptables
    def load(self, rules):
        inst = iptables.Iptables(rules)
        return inst

    def test_find(self):
        r1 = Rule(chain='INPUT', num='9', pkts='0', bytes='0', target='DROP', prot='all', opt='--', inp='eth+', out='*', source='2.2.2.2', destination='0.0.0.0/0', extra='')
        r2 = Rule(chain='INPUT', num='10', pkts='0', bytes='0', target='ACCEPT', prot='tcp', opt='--', inp='*', out='*', source='3.4.5.6', destination='0.0.0.0/0', extra='tcp spt:12345')
        r3 = Rule(chain='INPUT', num='1', pkts='14', bytes='840', target='DROP', prot='tcp', opt='--', inp='*', out='*', source='0.0.0.0/0', destination='0.0.0.0/0', extra='tcp dpt:7393')
        r4 = Rule(chain='OUTPUT', num='1', pkts='0', bytes='0', target='DROP', prot='all', opt='--', inp='*', out='tun+', source='0.0.0.0/0', destination='7.7.7.6', extra='')
        rules = [r1, r2, r3, r4]
        inst1 = self.load(rules)
        self.assertEqual( inst1.find({}), rules)
        self.assertEqual( inst1.find({'destination': ['0.0.0.0/0']}), [r1, r2, r3])
        self.assertEqual( inst1.find({'target': ['ACCEPT']}), [r2])
        self.assertEqual( inst1.find({'chain': ['OUTPUT']}), [r4])
        self.assertEqual( inst1.find({'chain': ['OUTPUT'], 'target':['ACCEPT']}), [])
        self.assertEqual( inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target':['ACCEPT']}), [r2])
        self.assertEqual( inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target':['ACCEPT', 'DROP']}), rules)
        self.assertEqual( inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target':['DROP'], 'extra': ['']}), [r1, r4])
        
    def test_create_rule(self):
        """Test creating Rule objects in various ways
        """
        r1 = Rule({'chain': 'INPUT', 'source': '1.2.3.4'})
        self.assertEquals(str(r1), "Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', extra='')")
        r2 = Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', extra='')
        self.assertEquals(str(r2), "Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', extra='')")
        r3 = Rule(['INPUT', None, None, None, None, 'all', '--', '*', '*', '1.2.3.4', '0.0.0.0/0', ''])
        self.assertEquals(str(r3), "Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', extra='')")


