import sys
from .pipeline import dummy_test_pipeline, another_test_pipeline, YetAnotherTestPipeline

if "pytest" in sys.modules:
    __all__ = ["dummy_test_pipeline", "another_test_pipeline", "YetAnotherTestPipeline"]
