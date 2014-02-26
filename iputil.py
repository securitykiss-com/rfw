import struct, socket

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



