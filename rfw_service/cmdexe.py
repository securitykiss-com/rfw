import subprocess, logging, re

log = logging.getLogger("rfw.log")





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
        if iface2:
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

# deprecated
#TODO use Iptables.find() search    
def rules_to_rcmds(rules):
    """Filter and convert the list of iptables.Rules to rcmd format like:
    {'action': 'DROP', 'ip1': '2.3.4.5', 'iface1': 'eth', 'chain': 'input'}
    rcmd is a simplified data model corresponding to rfw REST commands to allow quick lookups
    return set of frozenset of rcmd items
    """
    rcmds = set()
    for r in rules:
        # rfw originated rules may have only DROP/ACCEPT targets and do not specify protocol and do not have extra args like ports
        if r.target in ['DROP', 'ACCEPT'] and r.prot == 'all' and not r.extra:
            # Check if the rule matches rfw command format for particular chains. Ignore non-rfw rules
            if r.chain == 'INPUT':
                if r.destination == '0.0.0.0/0' and r.out == '*':
                    iface1 = r.inp
                    if iface1[-1] == '+':
                        iface1 = iface1[:-1]
                    if iface1 == '*':
                        iface1 = 'any'
                    rcmd = {'chain': r.chain.lower(), 'action': r.target, 'ip1': r.source, 'iface1': iface1}
                    #TODO check for duplicates here and log warning 
                    rcmds.add(frozenset(rcmd.items()))
    
            if r.chain == 'OUTPUT':
                if r.source == '0.0.0.0/0' and r.inp == '*' :
                    iface1 = r.out
                    if iface1[-1] == '+':
                        iface1 = iface1[:-1]
                    if iface1 == '*':
                        iface1 = 'any'
                    rcmd = {'chain': r.chain.lower(), 'action': r.target, 'ip1': r.destination, 'iface1': iface1}
                    #TODO check for duplicates here and log warning 
                    rcmds.add(frozenset(rcmd.items()))
    
            if r.chain == 'FORWARD':
                #TODO
                pass

    return rcmds



def apply_rule(modify, rcmd):
    log.debug('apply "{}" to the rule {}'.format(modify, rcmd))
    lcmd = iptables_construct(modify, rcmd)
    out = call(lcmd)
    if out:
        log.warn("Non empty output from the command: {}. The output: '{}'".format(lcmd, out))
    return out


def call(lcmd):
    try:
        log.debug('Call: {}'.format(' '.join(lcmd)))
        out = subprocess.check_output(lcmd, stderr=subprocess.STDOUT)
        if out: 
            log.debug("Call output: {}".format(out))
        return out
    except subprocess.CalledProcessError, e:
        log.error("Error code {} returned when called '{}'. Command output: '{}'".format(e.returncode, e.cmd, e.output))
        raise e





