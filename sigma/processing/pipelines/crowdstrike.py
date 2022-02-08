from sigma.processing.conditions import IncludeFieldCondition, MatchStringCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation, DetectionItemFailureTransformation, DropDetectionItemTransformation, FieldMappingTransformation, ReplaceStringTransformation
from sigma.processing.pipelines.common import logsource_windows_network_connection, logsource_windows_network_connection_initiated, logsource_windows_process_creation

cond_field_parentbasefilename = IncludeFieldCondition(fields=["ParentBaseFileName"])

def crowdstrike_fdr_pipeline():
    return ProcessingPipeline(
        name="Generic Log Sources to CrowdStrike Splunk Transformation",
        priority=10,
        items=[
            # Process Creation
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

            # Network Connection
            ProcessingItem(
                identifier="cs_network_connection_eventtype",
                transformation=AddConditionTransformation({
                    "event_simpleName": "NetworkConnectionIP4",
                }),
                rule_conditions=[
                    logsource_windows_network_connection(),
                    logsource_windows_network_connection_initiated(True),
                ]
            ),
            ProcessingItem(
                identifier="cs_network_connection_eventtype",
                transformation=AddConditionTransformation({
                    "event_simpleName": "NetworkReceiveAcceptIP4",
                }),
                rule_conditions=[
                    logsource_windows_network_connection(),
                    logsource_windows_network_connection_initiated(False),
                ]
            ),
            ProcessingItem(
                identifier="cs_network_connection_fieldmapping",
                transformation=FieldMappingTransformation({
                    "DestinationIp": "RemoteAddressIP4",
                    "DestinationPort": "RemotePort",
                }),
                rule_conditions=[
                    logsource_windows_network_connection(),
                ]
            ),
            ProcessingItem(
                identifier="cs_network_connection_drop_initiated",
                transformation=DropDetectionItemTransformation(),
                rule_conditions=[
                    logsource_windows_network_connection(),
                ],
                detection_item_conditions=[
                    IncludeFieldCondition(fields=["Initiated"]),
                ],
            ),
            ProcessingItem(
                identifier="crowdstrike_network_connection_logsource",
                transformation=ChangeLogsourceTransformation(
                    category="network_connection",
                    product="windows",
                    service="crowdstrike",
                ),
                rule_conditions=[
                    logsource_windows_network_connection(),
                ]
            ),

            # ParentBaseFileName handling
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
        ]
    )