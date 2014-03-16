import subprocess, logging, re

log = logging.getLogger("rfw.log")

# TODO move to cmdparse ?
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


#TODO use Iptables.find() search    
def rules_to_rcmds(rules):
    """Convert list of rules in output format from iptables_list() to rcmd format like:
    {'action': 'DROP', 'ip1': '2.3.4.5', 'iface1': 'eth', 'chain': 'input'}
    return set of frozenset of rcmd items
    """
    rcmds = set()
    for rule in rules:
        chain = rule['chain']
        src = rule['source']
        dst = rule['destination']
        target = rule['target']
        iface_in = rule['in']
        iface_out = rule['out']
        prot = rule['prot']
        extra = rule['extra']

        # TODO In memory model of iptables rules:
        # 1. There is a raw data model (called rules) containing all rules from 'iptables -L' - this is output from iptables_list().
        # 2. Another simplified data model (called rcmds) with filtered rules corresponding to rfw REST commands. This one will be stored in memory for quick lookup and periodically recreated from actual iptables reading. If so, we need to serialize iptables_list() command in the queue.

        # rfw originated rules may have only DROP/ACCEPT targets and do not specify protocol and do not have extra args like ports
        if target in ['DROP', 'ACCEPT'] and prot == 'all' and not extra:
            # Check if the rule matches rfw command format for particular chains. Ignore non-rfw rules
            if chain == 'INPUT':
                if dst == '0.0.0.0/0' and iface_out == '*':
                    iface1 = iface_in
                    if iface1[-1] == '+':
                        iface1 = iface1[:-1]
                    if iface1 == '*':
                        iface1 = 'any'
                    rcmd = {'chain': chain.lower(), 'action': target, 'ip1': src, 'iface1': iface1}
                    #TODO check for duplicates here and log warning 
                    rcmds.add(frozenset(rcmd.items()))
    
            if chain == 'OUTPUT':
                if src == '0.0.0.0/0' and iface_in == '*' :
                    iface1 = iface_out
                    if iface1[-1] == '+':
                        iface1 = iface1[:-1]
                    if iface1 == '*':
                        iface1 = 'any'
                    rcmd = {'chain': chain.lower(), 'action': target, 'ip1': dst, 'iface1': iface1}
                    #TODO check for duplicates here and log warning 
                    rcmds.add(frozenset(rcmd.items()))
    
            if chain == 'FORWARD':
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





