"""Make the stdlib-only modules in scanner/ importable from the test suite."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scanner"))
