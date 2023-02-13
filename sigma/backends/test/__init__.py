from .backend import TextQueryTestBackend, MandatoryPipelineTestBackend
import sys
import os

if "pytest" in sys.modules:
    backends = {
        "test": TextQueryTestBackend,
        "test_mandatory": MandatoryPipelineTestBackend,
    }