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

import argparse



def parse_commandline():
    parser = argparse.ArgumentParser()
    # TODO We may need to suppress interpreting -h and --help options. rfwc iptables -h will display rfwc help. Minor issue
    # TODO capture all remaining args as a list
    parser.add_argument('--wait', action='store_true', help='Wait until rfw server processes pending items in job queue. Used for making synchronous batch calls')
    # user:password format as in curl
    parser.add_argument('--user', help='user:password for basic authentication if rfw local.server requires it')
    args = parser.parse_args()
    return args

def main():
    args = parse_commandline()
    print(args)



if __name__ == '__main__':
    main()
