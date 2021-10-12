from sigma.processing.conditions import IncludeFieldCondition, MatchStringCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation, DetectionItemFailureTransformation, FieldMappingTransformation, ReplaceStringTransformation
from sigma.processing.pipelines.common import logsource_windows_process_creation

cond_field_parentbasefilename = IncludeFieldCondition(fields=["ParentBaseFileName"])

def crowdstrike_splunk_pipeline():
    return ProcessingPipeline(
        name="Generic Log Sources to CrowdStrike Splunk Transformation",
        priority=10,
        items=[
            ProcessingItem(
                identifier="cs_process_creation_eventtype",
                transformation=AddConditionTransformation({
                    "event_simpleName": "ProcessRollup2",
                }),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ]
            ),
            ProcessingItem(
                identifier="cs_process_creation_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Image": "ImageFileName",
                    "ParentImage": "ParentBaseFileName",
                }),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ]
            ),
            ProcessingItem(
                identifier="cs_parentbasefilename_fail_completepath",
                transformation=DetectionItemFailureTransformation("Only file name of parent image is available in CrowdStrike events."),
                detection_item_conditions=[
                    cond_field_parentbasefilename,
                    MatchStringCondition(
                        cond="any",
                        pattern="^\\*\\\\[^\\\\]+$",
                        negate=True,
                    )
                ]
            ),
            ProcessingItem(
                identifier="cs_parentbasefilename_executable_only",
                transformation=ReplaceStringTransformation(
                    regex="^\\*\\\\([^\\\\]+)$",
                    replacement="\\1",
                ),
                detection_item_conditions=[
                    cond_field_parentbasefilename,
                ]
            ),
            ProcessingItem(
                identifier="crowdstrike_process_creation_logsource",
                transformation=ChangeLogsourceTransformation(
                    category="process_creation",
                    product="windows",
                    service="crowdstrike",
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ]
            ),
        ]
    )