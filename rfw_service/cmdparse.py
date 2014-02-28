import sys, logging, urlparse, re
import iputil

log = logging.getLogger("rfw.cmdparse")

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
    if not s:
        return ret

    #TODO add validation and error reporting. Currently wrong iface and ip are ignored    
    # errors to be reported in the result and not with exceptions
    m = re.match(r"/(\w{2,8}\d{0,3})(/.*|$)", s)
    #TODO consider adding config option to allow only specified interfaces
    if not m:
        ret['error'] = 'Incorrect interface name 1'
        return ret
    ret['iface1'] = m.group(1)
    s = m.group(2)
    if not s:
        return ret

    m = re.match(r"/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/.*|$)", s)
    if not m or not iputil.validate_ip(m.group(1)):
        ret['error'] = 'Incorrect IP address 1'
        return ret
    ret['ip1'] = m.group(1)
    s = m.group(2)
    if not s:
        return ret

    if ret.get('chain') == 'forward':
        m = re.match(r"/(\w{2,8}\d{0,3})(/.*|$)", s)
        if not m:
            ret['error'] = 'Incorrect interface name 2'
            return ret
        ret['iface2'] = m.group(1)
        s = m.group(2)
        if not s:
            return ret

        m = re.match(r"/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/.*|$)", s)
        if not m or not iputil.validate_ip(m.group(1)):
            ret['error'] = 'Incorrect IP address 2'
            return ret
        ret['ip2'] = m.group(1)
        s = m.group(2)
 
    return ret 

def parse_command_path(path):
    ret = _parse_command_path_raw(path)
    # save the work if the dict already contains error
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
    
    timeout = params.get('timeout')
    if timeout:
        m = re.match(r"(\d{1,9})([smhd]?)$", timeout)  # seconds, minutes, hours or days. If none given, seconds assumed.
        if not m:
            ret['error'] = 'Wrong timeout parameter value'
            return ret
        t = int(m.group(1))
        unit = m.group(2)
        multiplier = 1
        if unit == 'm':
            multiplier = 60
        elif unit == 'h':
            multiplier = 3600
        elif unit == 'd':
            multiplier = 86400
        ret['timeout'] = str(t * multiplier)

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
    {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '3600'}
    chain == input implies that ip1 is a source address
    chain == output implies that ip1 is a destination address
    """
    # split input to path and query
    parsed = urlparse.urlparse(url)
    path, query = parsed.path, parsed.query
    print("{:<30}{}".format("path part:", path))
    print("{:<30}{}".format("query part:", query))

    ret = parse_command_path(path)
    ret.update(parse_command_query(query))

    return ret 


if __name__ == '__main__':
    # Some minimum testing 
    def test_parse_command():
        assert parse_command("/") == {}
        assert parse_command("/blabla")['error']
        assert parse_command("/input") == {'chain': 'input'}
        assert parse_command("/input/") == {'chain': 'input'}
        assert parse_command("/input/11.22.33.44") == {'chain': 'input'}
        assert parse_command("/input/eth/11.22.33.44") == {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44'}
        assert parse_command("/input/eth/11.22.33.44/") == {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44'}
        assert parse_command("/input/eth/11.22.3333.44/") == {'chain': 'input', 'iface1': 'eth'}
        assert parse_command("/input/eth/11.22.33.4444/") == {'chain': 'input', 'iface1': 'eth'}
        assert parse_command("/inputer")['error'] 
        assert parse_command("/input/eth/11.22.33.44?timeout=3600") == {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '3600'}
        assert parse_command("/input/eth/11.22.33.44?timeout=20s") == {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '20'}
        assert parse_command("/input/eth/11.22.33.44?timeout=10m") == {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '600'}
        assert parse_command("/input/eth/11.22.33.44?timeout=2h") == {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '7200'}
        assert parse_command("/input/eth/11.22.33.44?timeout=2d") == {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '172800'}
        assert parse_command("/input/eth/11.22.33.44/?timeout=3600&wait=true") == {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '3600', 'wait': 'true'}
        assert parse_command("/input/eth/11.22.33.44/ppp") == {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44'}
        assert parse_command("/forward/eth/11.22.33.44/ppp") == {'chain': 'forward', 'iface1': 'eth', 'ip1': '11.22.33.44', 'iface2': 'ppp'}
        assert parse_command("/forward/eth/11.22.33.44/ppp12/") == {'chain': 'forward', 'iface1': 'eth', 'ip1': '11.22.33.44', 'iface2': 'ppp12'}
        assert parse_command("/forward/eth/11.22.33.44/ppp12/55.66.77.88") == {'chain': 'forward', 'iface1': 'eth', 'ip1': '11.22.33.44', 'iface2': 'ppp12', 'ip2': '55.66.77.88'}
        print(sys._getframe().f_code.co_name + " passed")

    test_parse_command()


