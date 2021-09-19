from sigma.processing.pipelines.common import logsource_windows_process_creation
from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

def sysmon_pipeline():
    return ProcessingPipeline(
        name="Generic Log Sources to Sysmon Transformation",
        priority=10,
        items=[
            ProcessingItem(
                identifier="sysmon_process_creation_eventid",
                transformation=AddConditionTransformation({
                    "EventID": 1,
                }),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ]
            ),
            ProcessingItem(
                identifier="sysmon_process_creation_logsource",
                transformation=ChangeLogsourceTransformation(
                    product="windows",
                    service="sysmon",
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ]
            ),
        ]
    )