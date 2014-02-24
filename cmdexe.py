import subprocess, logging, re

log = logging.getLogger("rfw.log")

def _convert_iface(iface):
    """Convert iface string like 'any', 'eth', 'eth0' to iptables iface naming like empty_string eth+, eth0. 
    """
    if iface == 'any':
        # do not append interface
        return ''
    else:
        # append '+' quantifier to iface
        if not iface[-1].isdigit():
            iface += '+'
        return iface




# modify is 'I' for Insert or 'D' for Delete
# rcmd is a dictionary like {'action': 'DROP', 'ip1': '2.3.4.5', 'iface1': 'eth', 'chain': 'input'}
# It is assumed that the inputs were validated and sanitized
def iptables_construct(modify, rcmd):
    lcmd = ['iptables']
    
    # rcmd must have at least modify, chain, iface1 and ip1
    assert 'chain' in rcmd and 'iface1' in rcmd and 'ip1' in rcmd and 'action' in rcmd
    assert modify in ['I', 'D']  # insert or delete
    chain = rcmd['chain'].upper()
    assert chain in ['INPUT', 'OUTPUT', 'FORWARD']

    lcmd.append('-' + modify)
    lcmd.append(chain)


    iface1 = rcmd['iface1']
    iface1type = '-o' if chain == 'OUTPUT' else '-i'
    iptf1 = _convert_iface(iface1)
    if iptf1:
        lcmd.append(iface1type)
        lcmd.append(iptf1)


    ip1 = rcmd['ip1']
    # ip1 is a destination address for OUTPUT chain and source address for INPUT and FORWARD
    ip1type = '-d' if chain == 'OUTPUT' else '-s'
    lcmd.append(ip1type)
    lcmd.append(ip1)

    if chain == 'FORWARD':
        # for FORWARD chain iface2 and ip2 are not mandatory
        iface2 = rcmd.get('iface2')
        iptf2 = _convert_iface(iface2)
        if iptf2:
            lcmd.append('-o')
            lcmd.append(iptf2)
        ip2 = rcmd.get('ip2')
        if ip2:
            lcmd.append('-d')
            lcmd.append(ip2)

    action = rcmd['action']
    assert action in ['DROP', 'ACCEPT']
    lcmd.append('-j')
    lcmd.append(action)
    return lcmd


def iptables_list():
    """List and parse iptables rules.
    return list of rules. Single rule is a dict like:
    {'opt': '--', 'destination': '0.0.0.0/0', 'target': 'DROP', 'chain': 'INPUT', 'prot': 'all', 'bytes': '0', 'source': '2.3.4.5', 'num': '1', 'in': 'eth+', 'pkts': '0', 'out': '*'}
    """
    rules = []
    out = call(['iptables', '-n', '-L', '-v', '--line-numbers'])
    chains = ['INPUT', 'OUTPUT', 'FORWARD']
    chain = None
    header = None
    for line in out.split('\n'):
        line = line.strip()
        #print("OUT: {}".format(line))
        if not line:
            chain = None  #on blank line reset current chain
            continue
        m = re.match(r"Chain (\w+) .*", line)
        if m and m.group(1) in chains:
            chain = m.group(1)
            continue
        if "source" in line and "destination" in line:
            headers = line.split()
            continue
        if chain:
            columns = line.split()
            if columns and len(headers) == len(columns) and columns[0].isdigit():
                rule = dict(zip(headers, columns))
                rule['chain'] = chain
                rules.append(rule)
    return rules
    
def rules_to_rcmds(rules):
    """Convert list of rules in output format from iptables_list() to command format like:
    {'action': 'DROP', 'ip1': '2.3.4.5', 'iface1': 'eth', 'chain': 'input'}
    """
    rcmds = []
    for rule in rules:
        chain = rule['chain']
        src = rule['source']
        dst = rule['destination']
        target = rule['target']
        iface_in = rule['in']
        iface_out = rule['out']
        prot = rule['prot']

        # TODO In memory model of iptables rules:
        # 1. There is a raw data model (called rules) containing all rules from 'iptables -L' - this is output from iptables_list().
        # 2. Another simplified data model (called rcmds) with filtered rules corresponding to rfw REST commands. This one will be stored in memory for quick lookup and periodically recreated from actual iptables reading. If so, we need to serialize iptables_list() command in the queue.

        # rfw originated rules may have only DROP/ACCEPT targets and do not specify protocol
        if target in ['DROP', 'ACCEPT'] and prot == 'all':
            # Check if the rule matches rfw command format for particular chains. Ignore non-rfw rules
            if chain == 'INPUT':
                if dst == '0.0.0.0/0' and iface_out == '*':
                    iface1 = iface_in
                    if iface1[-1] == '+':
                        iface1 = iface1[:-1]
                    if iface1 == '*':
                        iface1 = 'any'
                    rcmd = {'chain': chain.lower(), 'action': target, 'ip1': src, 'iface1': iface1}
                    rcmds.append(rcmd)
    
            if chain == 'OUTPUT':
                if src == '0.0.0.0/0' and iface_in == '*' :
                    iface1 = iface_out
                    if iface1[-1] == '+':
                        iface1 = iface1[:-1]
                    if iface1 == '*':
                        iface1 = 'any'
                    rcmd = {'chain': chain.lower(), 'action': target, 'ip1': dst, 'iface1': iface1}
                    rcmds.append(rcmd)
    
            if chain == 'FORWARD':
                #TODO
                pass

    return rcmds


            



        
    








def call(lcmd):
    try:
        out = subprocess.check_output(lcmd, stderr=subprocess.STDOUT)
        # print "call output: {}".format(out)
        return out
    except subprocess.CalledProcessError, e:
        #TODO convert to log.error
        print("Error code {} returned when called '{}'. Command output: '{}'".format(e.returncode, e.cmd, e.output))
        raise e



if __name__ == "__main__":
    print iptables_construct('I', {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'timeout': '3600'})
    print iptables_construct('I', {'chain': 'output', 'iface1': 'eth0', 'ip1': '11.22.33.44', 'timeout': '3600'})
    print iptables_construct('I', {'chain': 'input', 'iface1': 'any', 'ip1': '11.22.33.44', 'timeout': '3600'})
    print iptables_construct('D', {'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'timeout': '3600'})
    print iptables_construct('I', {'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'iface2': 'eth0', 'timeout': '3600'})
    print iptables_construct('I', {'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'ip2': '5.6.7.8', 'timeout': '3600'})
    print iptables_construct('I', {'chain': 'forward', 'iface1': 'ppp', 'ip1': '11.22.33.44', 'iface2': 'eth0', 'ip2': '5.6.7.8', 'timeout': '3600'})


