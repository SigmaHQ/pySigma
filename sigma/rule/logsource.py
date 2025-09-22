from dataclasses import dataclass, field
import dataclasses
from typing import Any, Optional
import sigma.exceptions as sigma_exceptions
from sigma.exceptions import SigmaRuleLocation, SigmaTypeError


@dataclass(frozen=True)
class SigmaLogSource:
    category: Optional[str] = field(default=None)
    product: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)
    definition: Optional[str] = field(default=None)
    source: Optional[SigmaRuleLocation] = field(default=None, compare=False)
    custom_attributes: Optional[dict[str, Any]] = field(default=None, compare=False)

    def __post_init__(self) -> None:
        """Ensures that log source is not empty."""
        if self.category is None and self.product is None and self.service is None:
            raise sigma_exceptions.SigmaLogsourceError(
                "Sigma log source can't be empty", source=self.source
            )
        if self.category and not isinstance(self.category, str):
            raise sigma_exceptions.SigmaLogsourceError(
                "Sigma log source category must be string", source=self.source
            )
        if self.product and not isinstance(self.product, str):
            raise sigma_exceptions.SigmaLogsourceError(
                "Sigma log source product must be string", source=self.source
            )
        if self.service and not isinstance(self.service, str):
            raise sigma_exceptions.SigmaLogsourceError(
                "Sigma log source service must be string", source=self.source
            )
        if self.definition and not isinstance(self.definition, str):
            raise sigma_exceptions.SigmaLogsourceError(
                "Sigma log source definition must be string", source=self.source
            )

    @classmethod
    def from_dict(
        cls, logsource: dict[str, str], source: Optional[SigmaRuleLocation] = None
    ) -> "SigmaLogSource":
        """Returns SigmaLogSource object from dict with fields."""
        custom_attributes = {
            k: v for k, v in logsource.items() if k not in set(cls.__dataclass_fields__.keys())
        }

        return cls(
            logsource.get("category"),
            logsource.get("product"),
            logsource.get("service"),
            logsource.get("definition"),
            source,
            custom_attributes if len(custom_attributes) > 0 else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            field.name: str(value)
            for field in dataclasses.fields(self)
            if (value := self.__getattribute__(field.name)) is not None
        }

    def __contains__(self, other: "SigmaLogSource") -> bool:
        """
        Matching of log source specifications. A log source contains another one if:

        * Both log sources are equal
        * The log source specifies less attributes than the other and the specified attributes are equal
        """
        if not isinstance(other, self.__class__):
            raise SigmaTypeError(
                "Containment check only allowed between log sources", source=self.source
            )

        if self == other:
            return True

        return (
            (self.category is None or self.category == other.category)
            and (self.product is None or self.product == other.product)
            and (self.service is None or self.service == other.service)
        )


class EmptyLogSource(SigmaLogSource):
    """
    Log sources can't be empty, but this class is used to represent an empty log source as dummy for error
    handling purposes.
    """

    def __post_init__(self) -> None:
        # Do not raise an error for empty log source
        pass
