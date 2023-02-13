import sys
from .pipeline import dummy_test_pipeline, another_test_pipeline

if "pytest" in sys.modules:
    pipelines = {
        "test": dummy_test_pipeline,
        "another_test": another_test_pipeline,
    }