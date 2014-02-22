import sys, logging, urlparse, re


log = logging.getLogger("rfw.log")

def parse_command_path(path):
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

    #TODO add validation and error reporting. Currently wrong iface and ip are ignored    
    m = re.match(r"/(\w{2,8}\d{0,3})(/.*|$)", s)
    if not m:
        return ret
    ret['iface1'] = m.group(1)
    s = m.group(2)

    m = re.match(r"/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/.*|$)", s)
    if not m:
        return ret
    ret['ip1'] = m.group(1)
    s = m.group(2)
 
    if ret.get('chain') == 'forward':
        m = re.match(r"/(\w{2,8}\d{0,3})(/.*|$)", s)
        if not m:
            return ret
        ret['iface2'] = m.group(1)
        s = m.group(2)

        m = re.match(r"/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/.*|$)", s)
        if not m:
            return ret
        ret['ip2'] = m.group(1)
        s = m.group(2)
 
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
    return dict with command elements
    """
    # split input to path and query
    parsed = urlparse.urlparse(url)
    path, query = parsed.path, parsed.query
    print "{:<30}{}".format("path part:", path)
    print "{:<30}{}".format("query part:", query)

    ret = parse_command_path(path)
    ret.update(parse_command_query(query))

    return ret 


if __name__ == '__main__':
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


