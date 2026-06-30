"""Make the modules in scanner/ and harness/ importable from the test suite."""
import os
import sys

_root = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_root, "scanner"))
sys.path.insert(0, os.path.join(_root, "harness"))
