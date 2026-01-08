from collections import defaultdict
from sigma.conditions import ConditionOR
from typing import (
    ClassVar,
    Literal,
    Optional,
    Tuple,
    Union,
    cast,
)
from dataclasses import InitVar, dataclass, field
import re
from sigma.processing.transformations.base import (
    DetectionItemTransformation,
    StringValueTransformation,
    ValueTransformation,
)
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.exceptions import (
    SigmaRegularExpressionError,
    SigmaValueError,
    SigmaConfigurationError,
)
from sigma.types import (
    Placeholder,
    SigmaBool,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SigmaType,
    SpecialChars,
)


@dataclass
class HashesFieldsDetectionItemTransformation(DetectionItemTransformation):
    """
    Transforms the 'Hashes' field in Sigma rules by creating separate detection items for each hash type.

    This transformation replaces the generic 'Hashes' field with specific fields for each hash algorithm,
    optionally prefixing the field names. It supports various hash formats and can auto-detect hash types
    based on their length.

    Attributes:
        valid_hash_algos (list[str]): List of supported hash algorithms.
        field_prefix (str): Prefix to add to the new field names.
        drop_algo_prefix (bool): If True, omits the algorithm name from the new field name.
        hash_lengths (dict[int, str]): Mapping of hash lengths to their corresponding algorithms.

    Example:
        Input:
            Hashes:
                - 'SHA1=5F1CBC3D99558307BC1250D084FA968521482025'
                - 'MD5=987B65CD9B9F4E9A1AFD8F8B48CF64A7'
        Output:
            FileSHA1: '5F1CBC3D99558307BC1250D084FA968521482025'
            FileMD5: '987B65CD9B9F4E9A1AFD8F8B48CF64A7'
    """

    valid_hash_algos: list[str]
    field_prefix: str = ""
    drop_algo_prefix: bool = False
    hash_lengths: ClassVar[dict[int, str]] = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        """
        Applies the transformation to a single detection item.

        Args:
            detection_item (SigmaDetectionItem): The detection item to transform.

        Returns:
            Optional[Union[SigmaDetection, SigmaDetectionItem]]: A new SigmaDetection object containing
            the transformed detection items, or None if no valid hashes were found.

        Raises:
            Exception: If no valid hash algorithms were found in the detection item.
        """
        if (
            isinstance(detection_item.value, SigmaString)
            or isinstance(detection_item.value, list)
            and all(isinstance(v, SigmaString) for v in detection_item.value)
        ):
            values = detection_item.value
            if not isinstance(values, list):
                values = [values]
            algo_dict = self._parse_hash_values(cast(list[SigmaString], values))

            if not algo_dict:
                raise Exception(
                    f"No valid hash algorithm found in Hashes field. Please use one of the following: {', '.join(self.valid_hash_algos)}"
                )

            return self._create_new_detection_items(algo_dict)
        else:
            return None

    def _parse_hash_values(self, values: list[SigmaString]) -> dict[str, list[str]]:
        """
        Parses the hash values from the detection item.

        Args:
            values (Union[SigmaString, list[SigmaString]]): The hash values to parse.

        Returns:
            dict[str, list[str]]: A dictionary mapping field names to lists of hash values.
        """
        algo_dict = defaultdict(list)

        for value in values:
            hash_algo, hash_value = self._extract_hash_algo_and_value(value.to_plain())
            if hash_algo:
                field_name = self._get_field_name(hash_algo)
                algo_dict[field_name].append(hash_value)

        return algo_dict

    def _extract_hash_algo_and_value(self, value: str) -> tuple[str, str]:
        """
        Extracts the hash algorithm and value from a string.

        Args:
            value (str): The string containing the hash algorithm and value.

        Returns:
            tuple[str, str]: A tuple containing the hash algorithm and value.
        """
        parts = value.split("|") if "|" in value else value.split("=")
        if len(parts) == 2:
            hash_algo, hash_value = parts
            hash_algo = hash_algo.lstrip("*").upper()
        else:
            hash_value = parts[0]
            hash_algo = self._determine_hash_algo_by_length(hash_value)

        return (hash_algo, hash_value) if hash_algo in self.valid_hash_algos else ("", hash_value)

    def _determine_hash_algo_by_length(self, hash_value: str) -> str:
        """
        Determines the hash algorithm based on the length of the hash value.

        Args:
            hash_value (str): The hash value to analyze.

        Returns:
            str: The determined hash algorithm, or an empty string if not recognized.
        """
        return self.hash_lengths.get(len(hash_value), "")

    def _get_field_name(self, hash_algo: str) -> str:
        """
        Generates the field name for a given hash algorithm.

        Args:
            hash_algo (str): The hash algorithm.

        Returns:
            str: The generated field name.
        """
        return f"{self.field_prefix}{'' if self.drop_algo_prefix else hash_algo}"

    def _create_new_detection_items(self, algo_dict: dict[str, list[str]]) -> SigmaDetection:
        """
        Creates new detection items based on the parsed hash values.

        Args:
            algo_dict (dict[str, list[str]]): A dictionary mapping field names to lists of hash values.

        Returns:
            SigmaDetection: A new SigmaDetection object containing the created detection items.
        """
        return SigmaDetection(
            detection_items=[
                SigmaDetectionItem(
                    field=k if k != "keyword" else None,
                    modifiers=[],
                    value=[SigmaString(x) for x in v],
                )
                for k, v in algo_dict.items()
                if k
            ],
            item_linking=ConditionOR,
        )


@dataclass
class ReplaceStringTransformation(StringValueTransformation):
    """
    Replace string part matched by regular expresssion with replacement string that can reference
    capture groups. Normally, the replacement operates on the plain string representation of the
    SigmaString. This allows also to include special characters and placeholders in the replacement.
    By enabling the skip_special parameter, the replacement is only applied to the plain string
    parts of a SigmaString and special characters and placeholders are left untouched. The
    interpret_special option determines for skip_special if special characters and placeholders are
    interpreted in the replacement result or not.

    The replacement is implemented with re.sub() and can use all features available there.
    """

    regex: str
    replacement: str
    skip_special: bool = False
    interpret_special: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        try:
            self.re = re.compile(self.regex)
        except re.error as e:
            raise SigmaRegularExpressionError(
                f"Regular expression '{self.regex}' is invalid: {str(e)}"
            ) from e

    def apply_string_value(self, field: Optional[str], val: SigmaString) -> SigmaString:
        if isinstance(val, SigmaString):
            if self.skip_special:
                return val.map_parts(
                    lambda s: self.re.sub(
                        self.replacement, cast(str, s)
                    ),  # filter function in second parameter ensures str type.
                    lambda p: isinstance(p, str),
                    self.interpret_special,
                )
            else:
                sigma_string_plain = str(val)
                replaced = self.re.sub(self.replacement, sigma_string_plain)
                postprocessed_backslashes = re.sub(r"\\(?![*?])", r"\\\\", replaced)
                if val.contains_placeholder():  # Preserve placeholders
                    return SigmaString(postprocessed_backslashes).insert_placeholders()
                else:
                    return SigmaString(postprocessed_backslashes)


@dataclass
class MapStringTransformation(StringValueTransformation):
    """
    Map static string value to one or multiple other strings.
    """

    mapping: dict[str, Union[str, list[str]]]

    def apply_string_value(
        self, field: Optional[str], val: SigmaString
    ) -> Optional[Union[SigmaType, list[SigmaType]]]:
        mapped = self.mapping.get(str(val), None)
        if isinstance(mapped, str):
            return SigmaString(mapped)
        elif isinstance(mapped, list):
            return [SigmaString(item) for item in mapped]
        else:
            return None


@dataclass
class RegexTransformation(StringValueTransformation):
    """
    Transform a string value to a case insensitive regular expression. The following methods are
    available and can be selected with the method parameter:

    * plain: Convert the string to a regular expression without any change to its case. In most
      cases this should result in a case-sensitive match of the string.
    * case_insensitive_flag: Add the case insensitive flag to the regular expression.
    * case_insensitive_brackets (default): Wrap each character in a bracket expression like [aA] to match
      both case variants.

    This transformation is intended to be used to emulate case insensitive matching in backends that
    don't support it natively.
    """

    method: Literal["plain", "ignore_case_flag", "ignore_case_brackets"] = "ignore_case_brackets"

    def __post_init__(self) -> None:
        if self.method not in type(self).__annotations__["method"].__args__:
            raise SigmaConfigurationError(
                f"Invalid method '{self.method}' for CaseInsensitiveRegexTransformation."
            )
        return super().__post_init__()

    def apply_string_value(self, field: Optional[str], val: SigmaString) -> Optional[SigmaType]:
        regex = ""

        # empty string can not be convert into a simple regex
        if val == "":
            return val

        for sc in val.s:  # iterate over all SigmaString components (strings and special chars)
            if isinstance(sc, str):  # if component is a string
                if (
                    self.method == "ignore_case_brackets"
                ):  # wrap each character in a bracket expression
                    regex += "".join(
                        f"[{c.lower()}{c.upper()}]" if c.isalpha() else re.escape(c) for c in sc
                    )
                else:
                    regex += re.escape(sc)
            elif (
                sc == SpecialChars.WILDCARD_MULTI
            ):  # if component is a wildcard, add it as regex .*
                regex += ".*"
            elif (
                sc == SpecialChars.WILDCARD_SINGLE
            ):  # if component is a single wildcard, add it as regex .
                regex += "."
            elif isinstance(sc, Placeholder):  # Placeholders are not allowed in regex
                raise SigmaConfigurationError(
                    f"Placeholder '{sc.name}' can't be converted to a regular expression. Please use a placeholder resolution transformation before."
                )
        if self.method == "ignore_case_flag":
            return SigmaRegularExpression(regex, {SigmaRegularExpressionFlag.IGNORECASE})
        else:
            return SigmaRegularExpression(regex)


@dataclass
class SetValueTransformation(ValueTransformation):
    """
    Set value to a fixed value. The type of the value can be enforced to `str` or `num` with the
    force_type parameter.
    """

    value: InitVar[Optional[Union[str, int, float, bool]]]
    force_type: Optional[Literal["str", "num"]] = None
    sigma_value: SigmaType = field(init=False)

    def __post_init__(self, value: Optional[Union[str, int, float, bool]]) -> None:
        if self.force_type is None:  # no type forced, use type of value
            if isinstance(value, str):
                self.sigma_value = SigmaString(value)
            elif isinstance(value, bool):
                self.sigma_value = SigmaBool(value)
            elif isinstance(value, (int, float)):
                self.sigma_value = SigmaNumber(value)
            elif value is None:
                self.sigma_value = SigmaNull()
            else:
                raise SigmaConfigurationError(
                    f"Unsupported value type '{type(value)}' for SetValueTransformation"
                )
        else:  # forced type
            if not isinstance(value, (str, int, float)):  # only allowed for certain types
                raise SigmaConfigurationError(
                    f"force_type '{self.force_type}' is only allowed for string and numeric values"
                )
            if self.force_type == "str":
                self.sigma_value = SigmaString(str(value))
            elif self.force_type == "num":
                try:
                    self.sigma_value = SigmaNumber(value)
                except SigmaValueError:
                    raise SigmaConfigurationError(
                        f"Value '{value}' can't be converted to number while initializing SimgaValueTransformation"
                    )
            else:
                raise SigmaConfigurationError(
                    f"Invalid force_type '{self.force_type}' in SigmaValueTransformation"
                )

        super().__post_init__()

    def apply_value(self, field: Optional[str], val: SigmaType) -> SigmaType:
        return self.sigma_value


@dataclass
class ConvertTypeTransformation(ValueTransformation):
    """
    Convert type of value. The conversion into strings and numbers is currently supported.
    """

    target_type: Literal["str", "num"]

    def apply_value(
        self, field: Optional[str], val: SigmaType
    ) -> Optional[Union[SigmaString, SigmaNumber, SigmaExpansion]]:
        if self.target_type == "str":
            if isinstance(val, SigmaExpansion):
                for i, entry in enumerate(val.values):
                    # avoid re-parsing entries that are already SigmaString
                    if not isinstance(entry, SigmaString):
                        val.values[i] = SigmaString(str(entry))

                return val

            # confirming correct structure, avoiding re-parsing
            if isinstance(val, SigmaString):
                return val

            return SigmaString(str(val))
        elif self.target_type == "num":
            try:
                if isinstance(val, SigmaExpansion):
                    for i, entry in enumerate(val.values):
                        val.values[i] = SigmaNumber(str(entry))

                    return val

                return SigmaNumber(str(val))
            except SigmaValueError:
                raise SigmaValueError(f"Value '{val}' can't be converted to number for {str(self)}")


@dataclass
class CaseTransformation(StringValueTransformation):
    """
    Transform a string value to a lower or upper or snake case.
    """

    method: Literal["lower", "upper", "snake_case"] = "lower"

    def __post_init__(self) -> None:
        if self.method not in type(self).__annotations__["method"].__args__:
            raise SigmaConfigurationError(f"Invalid method '{self.method}' for CaseTransformation.")
        return super().__post_init__()

    def apply_string_value(self, field: Optional[str], val: SigmaString) -> Optional[SigmaString]:

        if self.method == "snake_case":
            return val.snake_case()
        elif self.method == "lower":
            return val.lower()
        else:
            return val.upper()
