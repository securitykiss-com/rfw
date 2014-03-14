import inspect, re, subprocess, logging

# Follow the logging convention:
# - Modules intended as reusable libraries have names 'lib.<modulename>' what allows to configure single parent 'lib' logger for all libraries in the consuming application
# - Add NullHandler (since Python 2.7) to prevent error message if no other handlers present. The consuming app may add other handlers to 'lib' logger or its children.
log = logging.getLogger('lib.{}'.format(__name__))
log.addHandler(logging.NullHandler())

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

    # Consider it private method. To get the rules use: Iptables.load().rules
    @staticmethod
    def _iptables_list(ipt_path):
        """List and parse iptables rules.
        return list of rules. Single rule is a dict like:
        {'opt': '--', 'destination': '0.0.0.0/0', 'target': 'DROP', 'chain': 'INPUT', 'prot': 'all', 'bytes': '0', 'source': '2.3.4.5', 'num': '1', 'in': 'eth+', 'pkts': '0', 'out': '*', 'extra': ''}
        """
        rules = []
        out = subprocess.check_output([ipt_path, '-n', '-L', '-v', '--line-numbers'], stderr=subprocess.STDOUT)
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
                headers = line.split()
                headers.append('extra')
                assert len(headers) == 11, "len(headers) is {}".format(len(headers))
                continue
            if chain:
                columns = line.split()
                if columns and columns[0].isdigit():
                    # join all extra columns into one extra field
                    extra = " ".join(columns[10:])
                    columns = columns[:10]
                    columns.append(extra)
                    rule = dict(zip(headers, columns))
                    rule['chain'] = chain
                    rules.append(rule)
        return rules
    
   
    @staticmethod
    def rule_to_command(modify, rule):
        """Convert rule in format like:
        {'opt': '--', 'destination': '0.0.0.0/0', 'target': 'ACCEPT', 'chain': 'INPUT', 'extra': '', 'prot': 'tcp', 'bytes': '0', 'source': '1.2.3.4', 'num': '1', 'in': '*', 'pkts': '0', 'out': '*'}
        to command like (with modify='I'): 
        ['iptables', '-I', 'INPUT', '-p', 'tcp', '-d', '0.0.0.0/0', '-s', '1.2.3.4', '-j', 'ACCEPT']
        It is assumed that the rule has all fields and is from trusted source (from Iptables.find())
        """
        #TODO handle extras e.g. 'extra': 'tcp dpt:7373 spt:34543'
        #TODO add validations
        #TODO handle wildcards
        assert modify == 'I' or modify == 'D'
        chain = rule['chain']
        assert chain == 'INPUT' or chain == 'OUTPUT' or chain == 'FORWARD'
        lcmd = ['iptables']
        lcmd.append('-' + modify)
        lcmd.append(chain)
        prot = rule['prot']
        if prot != 'all':
            lcmd.append('-p')
            lcmd.append(prot)

        # TODO enhance. For now handle only source and destination port
        extra = rule['extra']
        if extra:
            es = extra.split()
            for e in es:
                if e[:4] == 'dpt:':
                    dport = e.split(':')[1]
                    lcmd.append('--dport')
                    lcmd.append(dport)
                if e[:4] == 'spt:':
                    sport = e.split(':')[1]
                    lcmd.append('--sport')
                    lcmd.append(sport)

        destination = rule['destination']
        if destination != '0.0.0.0/0':
            lcmd.append('-d')
            lcmd.append(destination)
        source = rule['source']
        if source != '0.0.0.0/0':
            lcmd.append('-s')
            lcmd.append(source)
        lcmd.append('-j')
        lcmd.append(rule['target'])
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
                rule_val = r[param]
                if rule_val not in vals:
                    matched_all = False
                    break
            if matched_all:
                ret.append(r)
        return ret





