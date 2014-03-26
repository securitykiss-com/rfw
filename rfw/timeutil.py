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

import re

def parse_interval(t):
    """Parse time interval t given as string in one of the following formats:
    - <number> representing number of seconds
    - <number>s representing number of seconds
    - <number>h representing number of hours
    - <number>d representing number of days
    Time can only be non-negative
    return converted number of seconds as integer or None if wrong format
    """
    t = t.strip()
    m = re.match(r"(\d{1,9})([smhd]?)$", t)  # seconds, minutes, hours or days. If none given, seconds assumed.
    if not m:
        return None
    t = int(m.group(1))
    unit = m.group(2)
    multiplier = 1
    if unit == 'm':
        multiplier = 60
    elif unit == 'h':
        multiplier = 3600
    elif unit == 'd':
        multiplier = 86400
    return t * multiplier
