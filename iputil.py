import struct, socket, re

def ip2long(s):
    """Convert IP address string to big-endian long
    """
    return struct.unpack("!L", socket.inet_aton(s))[0]


def long2ip(l):
    """Convert big-endian long representation of IP address to string
    """
    return socket.inet_ntoa(struct.pack("!L", l))

def mask2long(mask):
    """Convert numeric CIDR network mask to negative integer representation for bitwise operations.
    """
    assert isinstance(mask, (int, long)) and mask >= 0 and mask <= 32
    return -(1 << (32 - mask)) 

def in_iplist(ip, l):
    """Check if IP address is in the list.
    List l may contain individual IP addresses or CIDR ranges.
    """
    # no input validations here as it should be fast
    for item in l:
        if '/' in item:
            a, mask = item.split('/')
            m = mask2long(int(mask))
            # IP range contains IP address when masked range equals masked address
            if (ip2long(a) & m) == (ip2long(ip) & m):
                return True
        else:
            if item == ip:
                return True
    return False


def validate_ip_cidr(ip, allow_no_mask=False):
     """Check if the IP address range is correct in CIDR format: xxx.xxx.xxx.xxx/nn
     If allow_no_mask = True it accepts also individual IP address without network mask
     
     return validated and trimmed IP address range or False if not valid
     """
     if not ip:
         return False
     ip = ip.strip()
     m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/(\d{1,2})$|$)", ip)
     mask = m.group(6)
     if m and int(m.group(1)) < 256 and int(m.group(2)) < 256 and int(m.group(3)) < 256 and int(m.group(4)) < 256:
         if mask and int(mask) >= 0 and int(mask) <= 32:
             return ip
         if allow_no_mask and not mask:
             return ip
     return False

def validate_ip(ip):
     """Check if the IP address has correct format.
     
     return validated (and trimmed) IP address or False if not valid
     """
     if not ip:
         return False
     ip = ip.strip()
     m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
     if m and int(m.group(1)) < 256 and int(m.group(2)) < 256 and int(m.group(3)) < 256 and int(m.group(4)) < 256:
         return ip
     return False




def validate_port(port):
     """Port number format validator
     
     return validated port number as string or False if not valid
     """
     if not port:
         return False
     port = port.strip()
     if port.isdigit() and int(port) > 0 and int(port) < 65536:
         return port
     return False


