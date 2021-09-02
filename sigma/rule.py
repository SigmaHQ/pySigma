from dataclasses import dataclass, field
from typing import Optional, Union, Sequence, List, Set, Mapping, Type
from uuid import UUID
from enum import Enum, auto
from datetime import date
import yaml
from sigma.types import SigmaType, SigmaNull, SigmaString, SigmaNumber, SigmaRegularExpression, sigma_type
from sigma.modifiers import SigmaModifier, modifier_mapping, SigmaValueModifier, SigmaListModifier
from sigma.conditions import SigmaCondition, ConditionAND, ConditionOR, ConditionFieldEqualsValueExpression, ConditionFieldValueInExpression, ConditionValueExpression
import sigma.exceptions as sigma_exceptions

class SigmaStatus(Enum):
    STABLE       = auto()
    EXPERIMENTAL = auto()
    TEST         = auto()

class SigmaLevel(Enum):
    LOW      = auto()
    MEDIUM   = auto()
    HIGH     = auto()
    CRITICAL = auto()

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
    category : Optional[str] = field(default=None)
    product : Optional[str] = field(default=None)
    service : Optional[str] = field(default=None)

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

    By default all values are OR-linked but the 'all' modifier can be used to override this behavior.
    """
    field : Optional[str]       # if None, this is a keyword argument not bound to a field
    modifiers : List[Type[SigmaModifier]]
    value : List[Union[SigmaType]]
    value_linking : Union[Type[ConditionAND], Type[ConditionOR]] = ConditionOR
    applied_processing_items : Set[str] = field(init=False, compare=False, default_factory=set)

    def apply_modifiers(self):
        """
        Applies modifiers to detection and values
        """
        applied_modifiers = list()
        for modifier in self.modifiers:
            modifier_instance = modifier(self, applied_modifiers)
            if isinstance(modifier_instance, SigmaValueModifier):        # Value modifiers are applied to each value separately
                self.value = [
                    item
                    for val in self.value
                    for item in modifier_instance.apply(val)
                ]
            elif isinstance(modifier_instance, SigmaListModifier):       # List modifiers are applied to the whole value list at once
                self.value = modifier_instance.apply(self.value)
            else:       # pragma: no cover
                raise TypeError("Instance of SigmaValueModifier or SigmaListModifier was expected")     # This should only happen if wrong mapping is defined, therefore no test for this case
            applied_modifiers.append(modifier)

    @classmethod
    def from_mapping(
            cls,
            key : Optional[str],
            val : Union[
                List[Union[int, str]],
                Union[int, str],
                None,
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
            modifier_ids = list()
        else:               # key-value detection
            field, *modifier_ids = key.split("|")
            if field == "":
                field = None

        try:
            modifiers = [
                modifier_mapping[mod_id]
                for mod_id in modifier_ids
            ]
        except KeyError as e:
            raise sigma_exceptions.SigmaModifierError(f"Unknown modifier {str(e)}")

        if isinstance(val, (int, str)):     # value is plain, convert into single element list
            val = [val]
        elif val is None:
            val = [None]

        # Map Python types to Sigma typing classes
        # TODO: also map None values to SigmaNull
        val = [
            sigma_type(v)
            for v in val
        ]

        detection_item = cls(field, modifiers, val)
        detection_item.apply_modifiers()
        return detection_item

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

    def postprocess(self, detections : "SigmaDetections") -> Union[ConditionAND, ConditionOR, ConditionFieldEqualsValueExpression, ConditionFieldValueInExpression, ConditionValueExpression]:
        if len(self.value) == 0:    # no value: map to none type
            if self.field is None:
                raise sigma_exceptions.SigmaConditionError("Null value must be bound to a field")
            else:
                return ConditionFieldEqualsValueExpression(self.field, SigmaNull())
        if len(self.value) == 1:        # single value: return key/value or value-only expression
            if self.field is None:
                return ConditionValueExpression(self.value[0])
            else:
                return ConditionFieldEqualsValueExpression(self.field, self.value[0])
        else:     # more than one value, return logically linked values or an "in" expression
            # special case: "in" expression
            # field must be present and values must all be basic types without any special characters (e.g. wildcards)
            # to result in an "in" expression. Reason is, that most backend only support plain values in "in" expressions.
            if self.field is not None \
                and all([
                    isinstance(v, ( SigmaString, SigmaNumber ))
                    for v in self.value
                ]) \
                and not any([
                    v.contains_special()
                    for v in self.value
                    if isinstance(v, SigmaString)
                ]):
                return ConditionFieldValueInExpression(self.field, self.value)
            else:       # default case: AND/OR linked expressions
                if self.field is None:      # no field - only values
                    return self.value_linking([
                        ConditionValueExpression(v)
                        for v in self.value
                    ])
                else:                       # with field - field/value pairs
                    return self.value_linking([
                        ConditionFieldEqualsValueExpression(self.field, v)
                        for v in self.value
                    ])

    def add_applied_processing_item(self, processing_item : Optional["sigma.processing.pipeline.ProcessingItem"]):
        """Add identifier of processing item to set of applied processing items."""
        if processing_item is not None and processing_item.identifier is not None:
            self.applied_processing_items.add(processing_item.identifier)

    def was_processed_by(self, processing_item_id : str) -> bool:
        """Determines if detection item was processed by a processing item with the given id."""
        return processing_item_id in self.applied_processing_items

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
    item_linking : Union[Type[ConditionAND], Type[ConditionOR]] = field(init=False)

    def __post_init__(self):
        """Check detection validity."""
        if len(self.detection_items) == 0:
            raise sigma_exceptions.SigmaDetectionError("Detection is empty")

        type_set = { type(item) for item in self.detection_items }
        if SigmaDetectionItem in type_set:
            self.item_linking = ConditionAND
        else:
            self.item_linking = ConditionOR

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
            if { type(item) for item in definition }.issubset({ str, int }):    # list of values: create one detection item containing all values
                return cls(
                    detection_items=[
                        SigmaDetectionItem.from_value(definition)
                    ]
                )
            else:
                return cls(
                        detection_items=[
                            SigmaDetection.from_definition(item)                               # nested SigmaDetection in other cases
                            for item in definition
                            ]
                        )

    def postprocess(self, detections : "SigmaDetections") -> Union[ConditionAND, ConditionOR]:
        """Convert detection item into condition tree element"""
        items = [
            detection_item.postprocess(detections)
            for detection_item in self.detection_items
        ]
        if len(items) == 1:     # no boolean linking required, directly return single element
            return items[0]
        elif len(items) > 1:
            return self.item_linking(items)

    def add_applied_processing_item(self, processing_item : Optional["sigma.processing.pipeline.ProcessingItem"]):
        """Propagate processing item to all contained detection items."""
        for detection_item in self.detection_items:
            detection_item.add_applied_processing_item(processing_item)

@dataclass
class SigmaDetections:
    """Sigma detection section including named detections and condition."""
    detections : Mapping[str, List[SigmaDetection]]
    condition : List[str]

    def __post_init__(self):
        """Detections sanity checks"""
        if self.detections == dict():
            raise sigma_exceptions.SigmaDetectionError("No detections defined in Sigma rule")
        self.parsed_condition = [
            SigmaCondition(cond, self)
            for cond in self.condition
        ]

    @classmethod
    def from_dict(cls, detections : dict) -> "SigmaDetections":
        try:
            if isinstance(detections["condition"], list):
                condition = detections["condition"]
            else:
                condition = [ detections["condition"] ]
        except KeyError:
            raise sigma_exceptions.SigmaConditionError("Sigma rule must contain at least one condition")

        return cls(
                detections={
                    name: SigmaDetection.from_definition(definition)
                    for name, definition in detections.items()
                    if name != "condition"
                    },
                condition=condition,
                )

    def __getitem__(self, key : str) -> SigmaDetection:
        """Get detection by name"""
        return self.detections[key]

@dataclass
class SigmaRule:
    title : str
    id : Optional[UUID]
    status : Optional[SigmaStatus]
    description : Optional[str]
    references : List[str]
    tags : Optional[List[SigmaRuleTag]]
    author : Optional[str]
    date : Optional[date]
    logsource : SigmaLogSource
    detection : SigmaDetections
    fields : Optional[List[str]]
    falsepositives : Optional[List[str]]
    level : Optional[SigmaLevel]

    errors : List[sigma_exceptions.SigmaError] = field(default_factory=list)

    @classmethod
    def from_dict(cls, rule : dict, collect_errors : bool = False) -> "SigmaRule":
        """
        Convert Sigma rule parsed in dict structure into SigmaRule object.

        if collect_errors is set to False exceptions are collected in the errors property of the resulting
        SigmaRule object. Else the first recognized error is raised as exception.
        """
        errors = []
        # Rule identifier may be empty or must be valid UUID
        rule_id = rule.get("id")
        if rule_id is not None:
            try:
                rule_id = UUID(rule_id)
            except ValueError:
                errors.append(sigma_exceptions.SigmaIdentifierError("Sigma rule identifier must be an UUID"))

        # Rule level validation
        level = rule.get("level")
        if level is not None:
            try:
                level = SigmaLevel[level.upper()]
            except KeyError:
                errors.append(sigma_exceptions.SigmaLevelError(f"'{ level }' is no valid Sigma rule level"))

        # Rule status validation
        status = rule.get("status")
        if status is not None:
            try:
                status = SigmaStatus[status.upper()]
            except KeyError:
                errors.append(sigma_exceptions.SigmaStatusError(f"'{ status }' is no valid Sigma rule status"))

        # parse rule date if existing
        rule_date = rule.get("date")
        if rule_date is not None:
            try:
                rule_date = date(*(int(i) for i in rule_date.split("/")))
            except ValueError:
                try:
                    rule_date = date(*(int(i) for i in rule_date.split("-")))
                except ValueError:
                    errors.append(sigma_exceptions.SigmaDateError(f"Rule date '{ rule_date }' is invalid, must be yyyy/mm/dd or yyyy-mm-dd"))

        # parse log source
        try:
            logsource = SigmaLogSource.from_dict(rule["logsource"])
        except KeyError:
            errors.append(sigma_exceptions.SigmaLogsourceError("Sigma rule must have a log source"))
            logsource = None

        # parse detections
        try:
            detections = SigmaDetections.from_dict(rule["detection"])
        except KeyError:
            errors.append(sigma_exceptions.SigmaDetectionError("Sigma rule must have a detection definitions"))
            detections = None

        if not collect_errors and errors:
            raise errors[0]

        return cls(
                title = rule.get("title", ""),
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
                errors = errors,
                )

    @classmethod
    def from_yaml(cls, rule : str, collect_errors : bool = False) -> "SigmaRule":
        """Convert YAML input string with single document into SigmaRule object."""
        parsed_rule = yaml.safe_load(rule)
        return cls.from_dict(parsed_rule, collect_errors)