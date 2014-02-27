#!/usr/bin/env python

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
