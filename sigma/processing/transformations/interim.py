from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.conditions import ConditionAND, ConditionOR
from sigma.types import SigmaString
from sigma.modifiers import (
    SigmaContainsModifier,
    SigmaStartswithModifier,
    SigmaEndswithModifier,
)

class TargetObjectTransformation(DetectionItemTransformation):
    """
    Transforms a TargetObject field into a combination of ObjectName and OBJECTVALUENAME,
    handling various modifiers.
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> SigmaDetectionItem:
        if detection_item.field != "TargetObject":
            return detection_item

        if not detection_item.value or not isinstance(detection_item.value[0], SigmaString):
            return detection_item

        s_value = str(detection_item.value[0])
        modifiers = detection_item.modifiers

        # Equals (no modifier)
        if not modifiers:
            if "\\" in s_value:
                object_name, object_value = s_value.rsplit("\\", 1)
                return SigmaDetection(
                    detection_items=[
                        SigmaDetectionItem("ObjectName", [], value=[SigmaString(object_name)]),
                        SigmaDetectionItem("OBJECTVALUENAME", [], value=[SigmaString(object_value)]),
                    ],
                    item_linking=ConditionAND,
                )

        # StartsWith
        elif SigmaStartswithModifier in modifiers:
            if "\\" in s_value:
                name_part, value_part = s_value.rsplit("\\", 1)
                return SigmaDetection(
                    detection_items=[
                        SigmaDetectionItem("ObjectName", [], value=[SigmaString(name_part)]),
                        SigmaDetectionItem(
                            "OBJECTVALUENAME",
                            [SigmaStartswithModifier],
                            value=[SigmaString(value_part)],
                        ),
                    ],
                    item_linking=ConditionAND,
                )
            else:
                return SigmaDetectionItem(
                    "ObjectName", [SigmaStartswithModifier], value=[SigmaString(s_value)]
                )

        # EndsWith
        elif SigmaEndswithModifier in modifiers:
            if "\\" in s_value:
                name_part, value_part = s_value.rsplit("\\", 1)
                return SigmaDetection(
                    detection_items=[
                        SigmaDetectionItem(
                            "ObjectName", [SigmaEndswithModifier], value=[SigmaString(name_part)]
                        ),
                        SigmaDetectionItem("OBJECTVALUENAME", [], value=[SigmaString(value_part)]),
                    ],
                    item_linking=ConditionAND,
                )
            else:
                return SigmaDetectionItem(
                    "OBJECTVALUENAME", [SigmaEndswithModifier], value=[SigmaString(s_value)]
                )

        # Contains
        elif SigmaContainsModifier in modifiers:
            if "\\" in s_value:
                name_part, value_part = s_value.rsplit("\\", 1)
                # ObjectName|contains: 'foo\bar' OR (ObjectName|endswith: 'foo' AND OBJECTVALUENAME|startswith: 'bar')
                return SigmaDetection(
                    detection_items=[
                        SigmaDetectionItem(
                            "ObjectName", [SigmaContainsModifier], value=[SigmaString(s_value)]
                        ),
                        SigmaDetection(
                            detection_items=[
                                SigmaDetectionItem(
                                    "ObjectName",
                                    [SigmaEndswithModifier],
                                    value=[SigmaString(name_part)],
                                ),
                                SigmaDetectionItem(
                                    "OBJECTVALUENAME",
                                    [SigmaStartswithModifier],
                                    value=[SigmaString(value_part)],
                                ),
                            ],
                            item_linking=ConditionAND,
                        ),
                    ],
                    item_linking=ConditionOR,
                )
            else:
                # ObjectName|contains: 'value' OR OBJECTVALUENAME|contains: 'value'
                return SigmaDetection(
                    detection_items=[
                        SigmaDetectionItem(
                            "ObjectName", [SigmaContainsModifier], value=[SigmaString(s_value)]
                        ),
                        SigmaDetectionItem(
                            "OBJECTVALUENAME", [SigmaContainsModifier], value=[SigmaString(s_value)]
                        ),
                    ],
                    item_linking=ConditionOR,
                )

        return detection_item


class DuplicateTargetFilenameTransformation(DetectionItemTransformation):
    """
    Duplicates the TargetFilename field into an ObjectName field.
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> SigmaDetectionItem:
        if detection_item.field == "TargetFilename":
            return SigmaDetection(
                detection_items=[
                    detection_item,
                    SigmaDetectionItem(
                        "ObjectName",
                        detection_item.modifiers,
                        value=detection_item.value,
                    ),
                ],
                item_linking=ConditionOR,
            )
        return detection_item
