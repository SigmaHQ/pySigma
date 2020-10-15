from dataclasses import dataclass
from typing import Optional, Union, Sequence, List, Mapping, TypeVar, Type
from uuid import UUID
from enum import Enum
from datetime import date
import yaml
from sigma.types import SigmaString, SigmaNumber, SigmaRegularExpression
import sigma.exceptions as sigma_exceptions

SigmaStatus = Enum("SigmaStatus", "stable experimental test")
SigmaLevel = Enum("SigmaLevel", "low medium high critical")

@dataclass
class SigmaRuleTag:
    namespace : str
    name : str

    @classmethod
    def from_str(cls, tag : str) -> "SigmaRuleTag":
        """Build SigmaRuleTag class from plain text tag string."""
        ns, n = tag.split(".", maxsplit=1)
        return cls(ns, n)

@dataclass
class SigmaLogSource:
    category : Optional[str]
    product : Optional[str]
    service : Optional[str]

    def __post_init__(self):
        """Ensures that log source is not empty."""
        if self.category == None and self.product == None and self.service == None:
            raise sigma_exceptions.SigmaLogsourceError("Sigma log source can't be empty")

    @classmethod
    def from_dict(cls, logsource : dict) -> "SigmaLogSource":
        """Returns SigmaLogSource object from dict with fields."""
        return cls(
                logsource.get("category"),
                logsource.get("product"),
                logsource.get("service"),
                )

    def __contains__(self, other : "SigmaLogSource") -> bool:
        """
        Matching of log source specifications. A log source contains another one if:

        * Both log sources are equal
        * The log source specifies less attributes than the other and the specified attributes are equal
        """
        if not isinstance(other, self.__class__):
            raise TypeError("Containment check only allowed between log sources")

        if self == other:
            return True

        return (self.category is None or self.category == other.category) and \
               (self.product  is None or self.product  == other.product ) and \
               (self.service  is None or self.service  == other.service )

@dataclass
class SigmaDetectionItem:
    """
    Single Sigma detection definition
    
    A detection consists of:
    * an optional field name
    * a list of value modifiers that can also be empty
    * the mandatory value or a list of values (internally it's always a list of values)
    """
    field : Optional[str]       # if None, this is a keyword argument not bound to a field
    modifiers : List[str]
    value : List[Union[SigmaString, SigmaNumber, SigmaRegularExpression]]

    def __post_init__(self):
        if "re" in self.modifiers:       # re modifier is already consumed when created from mapping and doesn't appears in modifier chain
            raise sigma_exceptions.SigmaModifierError("Modifier 're' can only be used as single modifier")

    @classmethod
    def from_mapping(
            cls,
            key : Optional[str],
            val : Union[
                List[Union[int, str]],
                Union[int, str],
                ]
            ) -> "SigmaDetectionItem":
        """
        Constructs SigmaDetectionItem object from a mapping between field name containing
        modifiers and a value. This also supports keys containing only value modifiers
        which results in a keyword detection.

        The value accepts plain values as well as lists of values and resolves them into
        the value list always contained in a SigmaDetectionItem instance.
        """
        if key is None:     # no key at all means pure keyword detection without value modifiers
            field = None
            modifiers = list()
        else:               # key-value detection
            field, *modifiers = key.split("|")
            if field == "":
                field = None

        if isinstance(val, (int, str)):     # value is plain, convert into single element list
            val = [val]

        if len(modifiers) == 1 and modifiers[0] == "re":      # Regular expressions
            modifiers = []
            val = [
                SigmaRegularExpression(str(v))
                for v in val
            ]
        else:                                               # Map Python types to Sigma typing classes
            val = [
                SigmaNumber(v) if isinstance(v, int)
                else SigmaString(v)
                for v in val
            ]

        return cls(field, modifiers, val)

    @classmethod
    def from_value(
            cls,
            val : Union[
                List[Union[int, str]],
                Union[int, str],
                ]
            ) -> "SigmaDetectionItem":
        """Convenience method for from_mapping(None, value)."""
        return cls.from_mapping(None, val)

@dataclass
class SigmaDetection:
    """
    A detection is a set of atomic event defitionions represented by SigmaDetectionItem instances. SigmaDetectionItems
    of a SigmaDetection are OR-linked.

    A detection can be defined by:

    1. a mapping between field/value pairs that all should appear in matched events.
    2. a plain value
    3. a list of plain values or mappings defined and matched as in 1 where at least one of the items should appear in matched events.
    """
    detection_items : List[Union[SigmaDetectionItem, "SigmaDetection"]]

    @classmethod
    def from_definition(cls, definition : Union[Mapping, Sequence]) -> "SigmaDetection":
        """Instantiate an appropriate SigmaDetection object from a parsed Sigma detection definition."""
        if isinstance(definition, Mapping):     # key-value-definition (case 1)
            return cls(
                    detection_items=[
                        SigmaDetectionItem.from_mapping(key, val)
                        for key, val in definition.items()
                        ])
        elif isinstance(definition, (str, int)):    # plain value (case 2)
            return cls(detection_items=[SigmaDetectionItem.from_value(definition)])
        elif isinstance(definition, Sequence):  # list of items (case 3)
            return cls(
                    detection_items=[
                        SigmaDetectionItem.from_value(item) if isinstance(item, (str, int))     # SigmaDetectionItem in case of a plain value or a list of plain values
                        else SigmaDetection.from_definition(item)                               # nested SigmaDetection in other cases
                        for item in definition
                        ]
                    )

@dataclass
class SigmaDetections:
    """Sigma detection section including named detections and condition."""
    detections : Mapping[str, List[SigmaDetection]]
    condition : List[str]

    def __post_init__(self):
        """Detections sanity checks"""
        if self.detections == dict():
            raise sigma_exceptions.SigmaDetectionError("No detections defined in Sigma rule")

    @classmethod
    def from_dict(cls, detections : dict) -> "SigmaDetections":
        try:
            if isinstance(detections["condition"], list):
                condition = detections["condition"]
            else:
                condition = [ detections["condition"] ]
        except KeyError:
            raise sigma_exceptions.SigmaConditionError("Sigma rule must contain at least one condition")
        del detections["condition"]

        return cls(
                detections={
                    name: SigmaDetection.from_definition(definition)
                    for name, definition in detections.items()
                    },
                condition=condition,
                )

@dataclass
class SigmaRule:
    title : str
    id : Optional[UUID]
    status : Optional[SigmaStatus]
    description : Optional[str]
    references : List[str]
    tags : Optional[List[SigmaRuleTag]]
    author : Optional[str]
    date : date
    logsource : SigmaLogSource
    detection : SigmaDetections
    fields : Optional[List[str]]
    falsepositives : Optional[List[str]]
    level : Optional[SigmaLevel]

    @classmethod
    def from_dict(cls, rule : dict) -> "SigmaRule":
        """Convert Sigma rule parsed in dict structure into SigmaRule object."""
        # Rule identifier may be empty or must be valid UUID
        rule_id = rule.get("id")
        if rule_id is not None:
            try:
                rule_id = UUID(rule_id)
            except ValueError:
                raise sigma_exceptions.SigmaIdentifierError("Sigma rule identifier must be an UUID")

        # Rule level validation
        level = rule.get("level")
        if level is not None:
            try:
                level = SigmaLevel[level]
            except KeyError:
                raise sigma_exceptions.SigmaLevelError(f"'{ level }' is no valid Sigma rule level")

        # Rule status validation
        status = rule.get("status")
        if status is not None:
            try:
                status = SigmaStatus[status]
            except KeyError:
                raise sigma_exceptions.SigmaStatusError(f"'{ status }' is no valid Sigma rule status")

        # parse rule date if existing
        rule_date = rule.get("date")
        if rule_date is not None:
            try:
                rule_date = date(*(int(i) for i in rule_date.split("/")))
            except ValueError:
                try:
                    rule_date = date(*(int(i) for i in rule_date.split("-")))
                except ValueError:
                    raise sigma_exceptions.SigmaDateError(f"Rule date '{ rule_date }' is invalid, must be yyyy/mm/dd or yyyy-mm-dd")

        # parse log source
        try:
            logsource = SigmaLogSource.from_dict(rule["logsource"])
        except KeyError:
            raise sigma_exceptions.SigmaLogsourceError("Sigma rule must have a log source")

        # parse detections
        try:
            detections = SigmaDetections.from_dict(rule["detection"])
        except KeyError:
            raise sigma_exceptions.SigmaDetectionError("Sigma rule must have a detection definitions")

        return cls(
                title = rule["title"],
                id = rule_id,
                level = level,
                status = status,
                description = rule.get("description"),
                references = rule.get("references"),
                tags = [ SigmaRuleTag.from_str(tag) for tag in rule.get("tags", list()) ],
                author = rule.get("author"),
                date = rule_date,
                logsource = logsource,
                detection = detections,
                fields = rule.get("fields"),
                falsepositives = rule.get("falsepositives"),
                )

    @classmethod
    def from_yaml(cls, rule : str) -> "SigmaRule":
        """Convert YAML input string with single document into SigmaRule object."""
        parsed_rule = yaml.safe_load(rule)
        return cls.from_dict(parsed_rule)