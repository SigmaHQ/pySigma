from dataclasses import dataclass, field
from typing import ClassVar, Dict, List
from sigma.rule import SigmaDetectionItem, SigmaRule
from sigma.types import SigmaNumber

from sigma.validators.base import SigmaDetectionItemValidator, SigmaValidationIssue, SigmaValidationIssueSeverity

sysmon_to_generic_logsource_mapping: Dict[int, str] = {
    1: "process_creation",
    2: "file_change",
    3: "network_connection",
    5: "process_termination",
    6: "driver_load",
    7: "image_load",
    8: "create_remote_thread",
    9: "raw_access_thread",
    10: "process_access",
    11: "file_event",
    12: "registry_add",
    12: "registry_delete",
    13: "registry_set",
    14: "registry_rename",
    12: "registry_event",
    13: "registry_event",
    14: "registry_event",
    15: "create_stream_hash",
    17: "pipe_created",
    18: "pipe_created",
    19: "wmi_event",
    20: "wmi_event",
    21: "wmi_event",
    22: "dns_query",
    23: "file_delete",
    26: "file_delete",
    24: "clipboard_capture",
}
disallowed_sysmon_event_ids = frozenset(sysmon_to_generic_logsource_mapping.keys())

@dataclass
class SysmonInsteadOfGenericLogsourceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Usage of Sysmon with EventID instead of generic log source"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    event_id: int
    generic_logsource: str = field(init=False, compare=False)

    def __post_init__(self):
        try:
            self.generic_logsource = sysmon_to_generic_logsource_mapping[self.event_id]
        except KeyError:
            raise ValueError(f"{ self.event_id } is not a disallowed Sysmon event identifier.")
        return super().__post_init__()

class SysmonInsteadOfGenericLogsourceValidator(SigmaDetectionItemValidator):
    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.logsource.service == "sysmon":
            return super().validate(rule)
        else:       # don't conduct any further checks if rule has no Sysmon logsource.
            return []

    def validate_detection_item(self, detection_item: SigmaDetectionItem) -> List[SigmaValidationIssue]:
        if detection_item.field == "EventID":
            return [
                SysmonInsteadOfGenericLogsourceIssue(rules=[ self.rule ], event_id=event_id.number)
                for event_id in detection_item.value
                if isinstance(event_id, SigmaNumber) and event_id.number in disallowed_sysmon_event_ids
            ]
        else:
            return []