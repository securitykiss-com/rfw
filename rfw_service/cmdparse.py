import sys, logging, urlparse, re
import iputil, timeutil, iptables
from iptables import Rule

log = logging.getLogger("rfw.cmdparse")


def convert_iface(iface):
    """Convert iface string like 'any', 'eth', 'eth0' to iptables iface naming like *, eth+, eth0. 
    """
    if iface == 'any':
        return '*'
    else:
        # append '+' quantifier to iface
        if not iface[-1].isdigit():
            iface += '+'
        return iface



# errors to be reported in the result and not with exceptions
def _parse_command_path_raw(path):
    s = path
    ret = {}
    if s == '/':
        return ret
    m = re.match(r"/(input|output|forward)(/.*|$)", s)
    if not m:
        ret['error'] = 'Incorrect chain name'
        return ret
    ret['chain'] = m.group(1)
    s = m.group(2)
    if not s or s == '/':
        return ret

    m = re.match(r"/(\w{2,8}\d{0,3})(/.*|$)", s)
    #TODO consider adding config option to allow only specified interfaces
    if not m:
        ret['error'] = 'Incorrect interface name 1'
        return ret
    ret['iface1'] = m.group(1)
    s = m.group(2)
    if not s or s == '/':
        return ret

    m = re.match(r"/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/.*|$)", s)
    if not m or not iputil.validate_ip(m.group(1)):
        ret['error'] = 'Incorrect IP address 1'
        return ret
    ret['ip1'] = m.group(1)
    s = m.group(2)
    if not s or s == '/':
        return ret

    if ret.get('chain') == 'forward':
        m = re.match(r"/(\w{2,8}\d{0,3})(/.*|$)", s)
        if not m:
            ret['error'] = 'Incorrect interface name 2'
            return ret
        ret['iface2'] = m.group(1)
        s = m.group(2)
        if not s or s == '/':
            return ret

        m = re.match(r"/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/.*|$)", s)
        if not m or not iputil.validate_ip(m.group(1)):
            ret['error'] = 'Incorrect IP address 2'
            return ret
        ret['ip2'] = m.group(1)
        s = m.group(2)
 
    return ret 


class PathError(Exception):
    def __init__(self, path, msg=''):
        Exception.__init__(self, 'Incorrect path: {}. {}'.format(path, msg))




# return dictionary:
# '/' -> tuple()
# '/list' -> ('list', '')
# '/list/input' -> ('list', 'input')
# '/drop/input/eth0/1.2.3.4' -> ('drop', Rule(...))

def parse_command_path(path):
    # split url path into parts, lowercase, trim trailing slash, return tuple
    def path_parts(path):
        path = path.strip().lower()
        if len(path) < 1 or path[0] != '/':
            raise PathError(path)
        if path[-1] == '/':
            path = path[:-1]
        p = map(str.strip, path.split('/'))
        p = tuple(p[1:])
        return p

    p = path_parts(path)

    action = p[0]

    # for path = '/'
    if action == '':
        if len(p) == 1:
            return tuple()
        else:
            raise PathError(path)
    
    if action.upper() in iptables.RULE_TARGETS:
        try:
            return action, build_rule(p)
        except ValueError, e:
            raise PathError(path, e.message)
    
    if p[0] == 'list':
        #TODO
        return action, 'TODO' 
        
    raise PathError(path)


# From the path parts tuple build and return Rule for drop/accept/reject type of command
# RULE_HEADERS =      ['chain', 'num', 'pkts', 'bytes', 'target', 'prot', 'opt', 'inp', 'out', 'source', 'destination', 'extra']
def build_rule(p):
    # There must be at least 4 parts like in /drop/input/eth0/1.2.3.4
    if len(p) < 4:
        raise ValueError('Not enough details to construct the rule')
    target = p[0].upper()
    if target not in iptables.RULE_TARGETS:
        raise ValueError('The action should be one of {}'.format(iptables.RULE_TARGETS))
    chain = p[1].upper()
    if chain not in iptables.RULE_CHAINS:
        raise ValueError('The chain should be one of {}'.format(iptables.RULE_CHAINS))
    iface1 = p[2]
    if len(iface1) > 16:
        raise ValueError('Interface name too long. Max 16 characters')
    iface1 = convert_iface(iface1)
    ip1 = iputil.validate_ip(p[3])
    if not ip1:
        raise ValueError('Incorrect IP address')

    
    mask1 = None
    iface2 = None
    ip2 = None
    mask2 = None
    if len(p) > 4:
        i = 4
        # optionally the netmask like: /drop/input/eth0/1.2.3.4/24
        if iputil.validate_mask(p[i]):
            mask1 = p[i]
            i = i + 1
        if len(p) > i:
            # iface2 for forward chain /drop/forward/eth0/1.2.3.4/eth1
            iface2 = p[i]
            i = i + 1
            if len(iface2) > 16:
                raise ValueError('Interface name too long. Max 16 characters')
            iface2 = convert_iface(iface2)
            if len(p) > i:
                ip2 = iputil.validate_ip(p[i])
                i = i + 1
                if not ip2:
                    raise ValueError('Incorrect IP address')
                if len(p) > i:
                    # now it must be the correct netmask if something was given after IP
                    if iputil.validate_mask(p[i]):
                        mask2 = p[i]
                    else:
                        raise ValueError('Incorrect netmask value')


    if chain in ['INPUT', 'OUTPUT']:
        if len(p) > 4 and not mask1:
            raise ValueError('Incorrect netmask value')
        if len(p) > 5:
            raise ValueError('Too many details for the {} chain'.format(chain))

    if chain == 'INPUT':
        inp = iface1
        out = '*'
        source = ip1
        if mask1:
            source = '{}/{}'.format(source, mask1)
        destination = '0.0.0.0/0'
    elif chain == 'OUTPUT':
        inp = '*'
        out = iface1
        source = '0.0.0.0/0'
        destination = ip1
        if mask1:
            destination = '{}/{}'.format(destination, mask1)
    elif chain == 'FORWARD':
        inp = iface1
        if iface2:
            out = iface2
        else:
            out = '*'
        source = ip1
        if mask1:
            source = '{}/{}'.format(ip1, mask1)
        destination = '0.0.0.0/0'
        if ip2:
            destination = ip2
        if mask2:
            destination = '{}/{}'.format(destination, mask2)
    else:
        assert 'Should not happen'

    return Rule({'target': target, 'chain': chain, 'inp': inp, 'out': out, 'source': source, 'destination': destination})

    
        
        
    




def old_parse_command_path(path):
    ret = _parse_command_path_raw(path)
    # do nothing if the dict already contains error
    if ret.get('error'):
        return ret
    
    # perform extra validations
    # 0.0.0.0 is a special address meaning any IP. It can be used only in FORWARD chain and only if the other FORWARD address is given specifically
    if ret.get('chain') == 'forward':
        if (not ret.get('ip1') or ret.get('ip1') == '0.0.0.0') and (not ret.get('ip2') or ret.get('ip2') == '0.0.0.0'):
            ret['error'] = 'With FORWARD chain at least one IP address must be given specifically (wildcard 0.0.0.0 does not count)'
            return ret
    else:
        if ret.get('ip1') == '0.0.0.0' or ret.get('ip2') == '0.0.0.0':
            ret['error'] = 'Wildcard IP address 0.0.0.0 can only be used with FORWARD chain'
            return ret
    return ret


def parse_command_query(query):
    params = dict(urlparse.parse_qsl(query))
    ret = {}
    
    expire = params.get('expire')
    if expire:
        interval = timeutil.parse_interval(expire)
        if interval is None:
            ret['error'] = 'Wrong expire parameter value'
            return ret
        ret['expire'] = str(interval)

    wait = params.get('wait')
    if wait:
        wait = wait.lower()
        if wait == 'true':
            ret['wait'] = wait
        else:
            ret['error'] = 'Incorrect wait parameter value'

    return ret



def parse_command(url):
    """
    return dict with command elements like:
    {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'expire': '3600'}
    chain == input implies that ip1 is a source address
    chain == output implies that ip1 is a destination address
    """
    # split input to path and query
    # path specifies the iptables Rule while query provides additional rfw parameters like expire or wait
    parsed = urlparse.urlparse(url)
    path, query = parsed.path, parsed.query

    rule = parse_command_path(path)
    directives = parse_command_query(query)

    return (rule, directives) 


