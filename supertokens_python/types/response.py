from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Literal, Protocol, TypeVar, runtime_checkable

from dataclasses_json import DataClassJsonMixin, LetterCase

Status = TypeVar("Status", bound=str)
Reason = TypeVar("Reason", bound=str)
_T = TypeVar("_T")


class APIResponse(ABC):
    @abstractmethod
    def to_json(self) -> Dict[str, Any]: ...


class GeneralErrorResponse(APIResponse):
    def __init__(self, message: str):
        self.status = "GENERAL_ERROR"
        self.message = message

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "message": self.message}


class CamelCaseDataclass(DataClassJsonMixin):
    dataclass_json_config = {  # type: ignore - library type issues
        "letter_case": LetterCase.CAMEL,  # type: ignore - library type issues
    }


"""
Protocol classes will allow use of older classes with these new types
They're like interfaces and allow classes to be interpreted as per their properties,
instead of their actual types, allowing use with the `StatusResponse` types.

Issue: Generic Protocols require the generic to be `invariant` - types need to be exact
Types defined as `StatusResponse[Literal["A", "B"]]`, and only one of these is returned.
This requires the generic to be `covariant`, which is not allowed in Protocols.

Solution: Refactor the types to be `StatusResponse[Literal["A"]] | StatusResponse[Literal["B"]]`
"""


@runtime_checkable
class HasStatus(Protocol[Status]):
    status: Status


@runtime_checkable
class HasErr(Protocol[Status]):
    err: Status


@runtime_checkable
class HasReason(Protocol[Status]):
    reason: Status


# Pylance complains about incompatible overrides between `APIResponse` and `DataClassJsonMixin`'s `to_json`
# implementation. The type-ignores are unavoidable to allow things to work without lint errors.
# TODO: Figure out a way to subclass from `APIResponse` and make it compatible with `DataClassJsonMixin`
@dataclass
class StatusResponse(CamelCaseDataclass, HasStatus[Status]):  # type: ignore
    """
    Generic response object with a `status` field.
    """

    status: Status


@dataclass
class StatusReasonResponse(StatusResponse[Status], HasReason[Reason]):
    """
    Generic error response object with `status` and `reason` fields.
    """

    reason: Reason


@dataclass
class StatusErrResponse(StatusResponse[Status]):
    """
    Generic error response object with `status` and `err` fields.
    """

    err: str


@dataclass
class OkResponse(StatusResponse[Literal["OK"]]):
    """
    Basic success response object with `status = "OK"`
    """

    status: Literal["OK"]
