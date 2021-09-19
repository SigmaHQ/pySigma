from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation, FieldMappingTransformation
from sigma.processing.pipelines.common import logsource_windows_process_creation

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
                }),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ]
            ),
            ProcessingItem(
                identifier="sysmon_process_creation_logsource",
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