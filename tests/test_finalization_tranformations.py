from sigma.processing.finalization import ConcatenateQueriesFinalizer
from .test_processing_transformations import dummy_pipeline, sigma_rule


def test_concatenate_queries_tranformation(dummy_pipeline):
    transformation = ConcatenateQueriesFinalizer(separator="', '", prefix="('", suffix="')")
    assert (
        transformation.apply(dummy_pipeline, ['field1="value1"', 'field2="value2"'])
        == """('field1="value1"', 'field2="value2"')"""
    )
