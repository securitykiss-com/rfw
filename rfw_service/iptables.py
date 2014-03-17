import inspect, re, subprocess, logging
from collections import namedtuple

# Follow the logging convention:
# - Modules intended as reusable libraries have names 'lib.<modulename>' what allows to configure single parent 'lib' logger for all libraries in the consuming application
# - Add NullHandler (since Python 2.7) to prevent error message if no other handlers present. The consuming app may add other handlers to 'lib' logger or its children.
log = logging.getLogger('lib.{}'.format(__name__))
log.addHandler(logging.NullHandler())

# note that the 'in' attribute from iptables output was renamed to 'inp' to avoid python keyword clash
IPTABLES_HEADERS =  ['num', 'pkts', 'bytes', 'target', 'prot', 'opt', 'in', 'out', 'source', 'destination'] 
RULE_HEADERS =      ['chain', 'num', 'pkts', 'bytes', 'target', 'prot', 'opt', 'inp', 'out', 'source', 'destination', 'extra']

RuleProto = namedtuple('Rule', RULE_HEADERS)


class Rule(RuleProto):
    """Lightweight immutable value object to store iptables rule
    """
    def __new__(_cls, props):
        """Construct Rule tuple from a list or a dictionary
        """
        if isinstance(props, list):
            return RuleProto.__new__(_cls, *props)
        elif isinstance(props, dict):
            nones = [None] * len(RuleProto._fields)
            dkeys = dict(zip(RuleProto._fields, nones))
            dkeys.update(props)
            return RuleProto.__new__(_cls, **dkeys)
        else:
            raise ValueError('The props argument in Rule constructor should be a list or dictionary')


class Iptables:

    def __init__(self, rules):
        # check the caller function name - the poor man's private constructor
        if inspect.stack()[1][3] == 'load':
            self.rules = rules
        else:
            raise Exception("Use Iptables.load() to create an instance with loaded current list of rules")

    @staticmethod
    def load(ipt_path='iptables'):
        rules = Iptables._iptables_list(ipt_path)
        inst = Iptables(rules)
        return inst

    @staticmethod
    def verify_install(ipt_path):
        """Check if iptables installed
        """
        try:
            subprocess.check_output([ipt_path, '-h'], stderr=subprocess.STDOUT)
        except OSError, e:
            raise Exception("Could not find {}. Check if it is correctly installed and if the path is correct.".format(ipt_path))

    @staticmethod
    def verify_permission(ipt_path):
        """Check if root - iptables installed but cannot list rules
        """
        try:
            subprocess.check_output([ipt_path, '-n', '-L', 'OUTPUT'], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError, e:
            raise Exception("No sufficient permission to run {}. You must be root.".format(ipt_path))

    @staticmethod
    def verify_original(ipt_path):
        #TODO check if iptables is pointing to original iptables program (and not to rfwc)
        pass

    # Don't use directly. To get the rules use: Iptables.load().rules
    # TODO Convert rule from dict to namedtuple (mytuple._asdict() and Tuplename(**mydict))
    @staticmethod
    def _iptables_list(ipt_path):
        """List and parse iptables rules.
        return list of rules of type Rule.
        """
        rules = []
        out = subprocess.check_output([ipt_path, '-n', '-L', '-v', '-x', '--line-numbers'], stderr=subprocess.STDOUT)
        chains = ['INPUT', 'OUTPUT', 'FORWARD']
        chain = None
        header = None
        for line in out.split('\n'):
            line = line.strip()
            if not line:
                chain = None  #on blank line reset current chain
                continue
            m = re.match(r"Chain (\w+) .*", line)
            if m and m.group(1) in chains:
                chain = m.group(1)
                continue
            if "source" in line and "destination" in line:
                # check if iptables output headers make sense 
                #print(line.split())
                #print(IPTABLES_HEADERS)
                assert line.split()  == IPTABLES_HEADERS
                continue
            if chain:
                columns = line.split()
                if columns and columns[0].isdigit():
                    # join all extra columns into one extra field
                    extra = " ".join(columns[10:])
                    columns = columns[:10]
                    columns.append(extra)
                    columns.insert(0, chain)
                    #rule = dict(zip(RULE_HEADERS, columns))
                    #rule['chain'] = chain
                    rule = Rule(columns)
                    rules.append(rule)
        return rules
    
   
    @staticmethod
    def rule_to_command(modify, r):
        """Convert Rule object r to command like (with modify='I' or modify='D'): 
        ['iptables', '-I', 'INPUT', '-p', 'tcp', '-d', '0.0.0.0/0', '-s', '1.2.3.4', '-j', 'ACCEPT']
        It is assumed that the rule is from trusted source (from Iptables.find())
        """
        #TODO handle extras e.g. 'extra': 'tcp dpt:7373 spt:34543'
        #TODO add validations
        #TODO handle wildcards
        assert modify == 'I' or modify == 'D'
        assert r.chain == 'INPUT' or r.chain == 'OUTPUT' or r.chain == 'FORWARD'
        lcmd = ['iptables']
        lcmd.append('-' + modify)
        lcmd.append(r.chain)
        if r.prot != 'all':
            lcmd.append('-p')
            lcmd.append(r.prot)

        # TODO enhance. For now handle only source and destination port
        if r.extra:
            es = r.extra.split()
            for e in es:
                if e[:4] == 'dpt:':
                    dport = e.split(':')[1]
                    lcmd.append('--dport')
                    lcmd.append(dport)
                if e[:4] == 'spt:':
                    sport = e.split(':')[1]
                    lcmd.append('--sport')
                    lcmd.append(sport)

        if r.destination != '0.0.0.0/0':
            lcmd.append('-d')
            lcmd.append(destination)
        if r.source != '0.0.0.0/0':
            lcmd.append('-s')
            lcmd.append(source)
        lcmd.append('-j')
        lcmd.append(r.target)
        return lcmd



    def find(self, query):
        """Find rules based on query
        For example:
            query = {'chain': ['INPUT', 'OUTPUT'], 'prot': ['all'], 'extra': ['']}
            is searching for the rules where:
            (chain == INPUT or chain == OUTPUT) and prot == all and extra == ''
        """
        ret = []
        for r in self.rules:
            matched_all = True    # be optimistic, if inner loop does not break, it means we matched all clauses
            for param, vals in query.items():
                #rule_val = r[param]
                rule_val = getattr(r, param)
                if rule_val not in vals:
                    matched_all = False
                    break
            if matched_all:
                ret.append(r)
        return ret



if __name__ == '__main__':
    ipt = Iptables.load()
    print(ipt.rules[0])
    found = ipt.find({'chain': 'INPUT'})
    print
    print(found)
    print
    print(ipt.rules)


