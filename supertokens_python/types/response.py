# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from abc import ABC, abstractmethod
from typing import Any, Dict, Generic, Literal, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel
from typing_extensions import Self

Status = TypeVar("Status", bound=str)
Reason = TypeVar("Reason", bound=str)


class APIResponse(ABC):
    @abstractmethod
    def to_json(self) -> Dict[str, Any]: ...


class GeneralErrorResponse(APIResponse):
    def __init__(self, message: str):
        self.status = "GENERAL_ERROR"
        self.message = message

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "message": self.message}


class CamelCaseBaseModel(APIResponse, BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        # Support interop between Pydantic and old classes
        arbitrary_types_allowed=True,
    )

    @classmethod
    def from_json(cls, obj: Dict[str, Any]) -> Self:
        """
        Converts a dictionary to a Pydantic model.
        """
        return cls.model_validate(obj)

    def to_json(self) -> Dict[str, Any]:
        """
        Converts the Pydantic model to a dictionary.
        """
        return self.model_dump(by_alias=True)


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


class StatusResponseBaseModel(CamelCaseBaseModel, Generic[Status]):
    status: Status


class StatusReasonResponseBaseModel(
    StatusResponseBaseModel[Status], Generic[Status, Reason]
):
    reason: Reason


class OkResponseBaseModel(StatusResponseBaseModel[Literal["OK"]]):
    status: Literal["OK"] = "OK"


class StatusErrResponseBaseModel(StatusResponseBaseModel[Status]):
    err: str
