import subprocess, logging

log = logging.getLogger("rfw.log")

def _convert_iface(iface):
    """Convert iface string like 'any', 'eth', 'eth0' to appropriate iptables contribution. Return the list. Possibly empty if iface == 'any'
    """
    if iface == 'any':
        # do not append interface
        return []
    else:
        # append '+' quantifier to iface
        if not iface[-1].isdigit():
            iface += '+'
        return ['-i', iface]




# rcmd is a dictionary with validated and sanitized input
def construct_iptables(rcmd):
    lcmd = ['iptables']
    
    # rcmd must have at least modify, chain, iface1 and ip1
    assert 'modify' in rcmd and 'chain' in rcmd and 'iface1' in rcmd and 'ip1' in rcmd and 'action' in rcmd
    modify = rcmd['modify']
    assert modify in ['I', 'D']  # insert or delete
    chain = rcmd['chain'].upper()
    assert chain in ['INPUT', 'OUTPUT', 'FORWARD']

    lcmd.append('-' + rcmd['modify'])
    lcmd.append(chain)


    iface1 = rcmd['iface1']
    lcmd.extend(_convert_iface(iface1))


    ip1 = rcmd['ip1']
    # ip1 is a destination address for OUTPUT chain and source address for INPUT and FORWARD
    ip1type = '-d' if chain == 'OUTPUT' else '-s'
    lcmd.append(ip1type)
    lcmd.append(ip1)

    if chain == 'FORWARD':
        # for FORWARD chain iface2 and ip2 are not mandatory
        iface2 = rcmd.get('iface2')
        if iface2:
            lcmd.extend(_convert_iface(iface2))
        ip2 = rcmd.get('ip2')
        if ip2:
            lcmd.append('-d')
            lcmd.append(ip2)


       
    action = rcmd['action']
    assert action in ['DROP', 'ACCEPT']
    lcmd.append('-j')
    lcmd.append(action)

    return lcmd


def call(lcmd):
    try:
        out = subprocess.check_output(lcmd, stderr=subprocess.STDOUT)
        print "call output: {}".format(out)
    except subprocess.CalledProcessError, e:
        #TODO convert to log.error
        print("Error code {} returned when called '{}'. Command output: '{}'".format(e.returncode, e.cmd, e.output))
        raise e



if __name__ == "__main__":
    #print construct_iptables({'chain': 'input'})
    print construct_iptables({'modify': 'I', 'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '3600'})
    print construct_iptables({'modify': 'I', 'chain': 'output', 'iface1': 'eth0', 'ip1': '11.22.33.44', 'timeout': '3600'})
    print construct_iptables({'modify': 'I', 'chain': 'input', 'iface1': 'any', 'ip1': '11.22.33.44', 'timeout': '3600'})
    print construct_iptables({'modify': 'D', 'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'timeout': '3600'})
    print construct_iptables({'modify': 'I', 'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'iface2': 'eth0', 'timeout': '3600'})
    print construct_iptables({'modify': 'I', 'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'ip2': '5.6.7.8', 'timeout': '3600'})
    print construct_iptables({'modify': 'I', 'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'iface2': 'eth0', 'ip2': '5.6.7.8', 'timeout': '3600'})


