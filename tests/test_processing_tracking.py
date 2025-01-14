import pytest
from sigma.processing.tracking import FieldMappingTracking


@pytest.fixture
def field_mapping_tracking():
    return FieldMappingTracking()


def test_field_mapping_tracking_single(field_mapping_tracking: FieldMappingTracking):
    field_mapping_tracking.add_mapping("fieldA", "mappedA")
    assert field_mapping_tracking["fieldA"] == {"mappedA"}


def test_field_mapping_tracking_cascaded(field_mapping_tracking: FieldMappingTracking):
    field_mapping_tracking.add_mapping("fieldA", "mappedA")
    field_mapping_tracking.add_mapping("mappedA", "mappedB")
    assert field_mapping_tracking["fieldA"] == {"mappedB"}
    assert field_mapping_tracking["mappedA"] == {"mappedB"}


def test_field_mapping_tracking_listitem_replaced(
    field_mapping_tracking: FieldMappingTracking,
):
    field_mapping_tracking.add_mapping("fieldA", ["mappedA", "mappedB", "mappedC"])
    field_mapping_tracking.add_mapping("mappedB", "mappedD")
    assert field_mapping_tracking["fieldA"] == {"mappedA", "mappedC", "mappedD"}


def test_field_mapping_tracking_merge():
    field_mapping_tracking = FieldMappingTracking()
    field_mapping_tracking.add_mapping("fieldA", "mappedA")
    field_mapping_tracking.add_mapping("mappedA", "mappedB")
    field_mapping_tracking.add_mapping("fieldB", "mappedC")

    other_field_mapping_tracking = FieldMappingTracking()
    other_field_mapping_tracking.add_mapping("mappedB", "mappedD")
    other_field_mapping_tracking.add_mapping("fieldC", "mappedE")

    field_mapping_tracking.merge(other_field_mapping_tracking)

    assert field_mapping_tracking["fieldA"] == {"mappedD"}
    assert field_mapping_tracking["fieldB"] == {"mappedC"}
    assert field_mapping_tracking["fieldC"] == {"mappedE"}
