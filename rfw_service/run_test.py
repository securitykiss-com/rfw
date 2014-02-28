#!/usr/bin/env python

#TODO run tests using setup.py
# http://stackoverflow.com/questions/17001010/how-to-run-unittest-discover-from-python-setup-py-test

#python -m unittest discover -s 'test' -p 'test_*.py'


import unittest

if __name__ == "__main__":
  suite = unittest.TestLoader().discover('.', pattern = "*test_*.py")
  unittest.TextTestRunner(verbosity=2).run(suite)

