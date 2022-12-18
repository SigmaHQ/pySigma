from .backend import TextQueryTestBackend
import sys
import os

if "pytest" in sys.modules:
    backends = {
        "test": TextQueryTestBackend,
    }