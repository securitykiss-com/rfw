import inspect, re, subprocess, logging

# Follow the logging convention:
# - Modules intended as reusable libraries have names 'lib.<modulename>' what allows to configure single parent 'lib' logger for all libraries in the consuming application
# - Add NullHandler (since Python 2.7) to prevent error message if no other handlers present. The consuming app may add other handlers to 'lib' logger or its children.
log = logging.getLogger('lib.{}'.format(__name__))
log.addHandler(logging.NullHandler())

class Iptables:

    def __init__(self, rules):
        # check caller function name
        if inspect.stack()[1][3] == 'load':
            self.rules = rules
        else:
            raise Exception("Use Iptables.load() to create an instance with loaded current list of rules")

    @staticmethod
    def load(ipt_path='iptables'):
        rules = _iptables_list(ipt_path)
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



