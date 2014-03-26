#!/usr/bin/env python
#
# Copyrite (c) 2014 SecurityKISS Ltd (http://www.securitykiss.com)  
#
# This file is part of rfw
#
# The MIT License (MIT)
#
# Yes, Mr patent attorney, you have nothing to do here. Find a decent job instead. 
# Fight intellectual "property".
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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


# deprecated
def in_iplist(ip, l):
    """Check if IP address is in the list.
    List l may contain individual IP addresses or CIDR ranges.
    """
    # no input validations here as it should be fast
    for item in l:
        if '/' in item:
            a, mask = item.split('/')
            m = mask2long(int(mask))
            # IP range contains IP address only if the masked range equals the masked address
            if (ip2long(a) & m) == (ip2long(ip) & m):
                return True
        else:
            if item == ip:
                return True
    return False

def ip_in_list(ip, l):
    """Check if IP address given as string is in the list.
    Both the ip and list may be individual IP addresses or CIDR ranges.
    """
    for c in l:
        if cidr_overlap(ip, c):
            return True
    return False


def cidr2range(c):
    """Convert CIDR string or single IP address as string to IP range given as tuple of integers (inclusive)
    """
    if '/' in c:
        a, mask = c.split('/')
        m = mask2long(int(mask))
        start = ip2long(a) & m
        end = start | ~m
    else:
        start = ip2long(c)
        end = start
    return (start, end)
    

def cidr_overlap(c1, c2):
    """Check if IP ranges given as CIDR strings overlap
    """
    r1_ipstart, r1_ipend = cidr2range(c1)
    r2_ipstart, r2_ipend = cidr2range(c2)
    return ip_ranges_overlap(r1_ipstart, r1_ipend, r2_ipstart, r2_ipend)
    



def ip_ranges_overlap(r1_ipstart, r1_ipend, r2_ipstart, r2_ipend):
    """Check if two IP ranges given as inclusive integer limited ranges overlap
    """
    if not isinstance(r1_ipstart, (int, long)) or not isinstance(r1_ipend, (int, long)) or not isinstance(r2_ipstart, (int, long)) or not isinstance(r2_ipend, (int, long)):
            raise ValueError('IP address should be integer')
    if r1_ipstart > r1_ipend or r2_ipstart > r2_ipend:
        raise ValueError('IP start cannot be greater than IP end. r1_ipstart={}, r1_ipend={}, r2_ipstart={}, r2_ipend={}'.format(r1_ipstart, r1_ipend, r2_ipstart, r2_ipend))
    return r1_ipstart <= r2_ipend and r2_ipstart <= r1_ipend



def validate_ip_cidr(ip, allow_no_mask=False):
     """Check if the IP address range is correct in CIDR format: xxx.xxx.xxx.xxx/nn
     If allow_no_mask = True it accepts also individual IP address without network mask
     
     return validated and trimmed IP address range as string or False if not valid
     """
     if not ip:
         return False
     ip = ip.strip()
     m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/(\d{1,2})$|$)", ip)
     mask = m.group(6)
     if m:
         a1, a2, a3, a4 = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
         if a1<256 and a2<256 and a3<256 and a4<256:
             ip_canon = "{}.{}.{}.{}".format(a1, a2, a3, a4)
             if mask and int(mask) >= 0 and int(mask) <= 32:
                 return "{}/{}".format(ip_canon, mask)
             if allow_no_mask and not mask:
                 return ip_canon
     return False

def validate_ip(ip):
     """Check if the IP address has correct format.
     
     return validated and trimmed IP address as string or False if not valid
     """
     if not ip:
         return False
     ip = ip.strip()
     m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
     if m:
         a1, a2, a3, a4 = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
         if a1<256 and a2<256 and a3<256 and a4<256:
             ip_canon = "{}.{}.{}.{}".format(a1, a2, a3, a4)
             return ip_canon
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

def validate_mask(mask):
    """Check if the netmask is valid

    return mask as string in the range [0, 32] or False if not valid
    """
    if not mask:
        return False
    mask = mask.strip()
    if mask.isdigit() and int(mask) >= 0 and int(mask) <= 32:
        return mask
    return False

def validate_mask_limit(mask):
    mask = validate_mask(mask)
    if mask and int(mask) > 8:
        return mask
    else:
        return False


