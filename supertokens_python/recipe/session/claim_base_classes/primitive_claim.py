# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union

from supertokens_python.types import MaybeAwaitable
from supertokens_python.utils import get_timestamp_ms

from ..interfaces import (
    ClaimValidationResult,
    JSONObject,
    JSONPrimitive,
    SessionClaim,
    SessionClaimValidator,
)

Primitive = TypeVar("Primitive", bound=JSONPrimitive)


class HasValueSCV(SessionClaimValidator):
    def __init__(
        self,
        id_: str,
        claim: SessionClaim[Primitive],
        val: Primitive,
        max_age_in_sec: Optional[int] = None,
    ):
        super().__init__(id_)
        self.claim: SessionClaim[Primitive] = claim  # to fix the type for pyright
        self.val = val
        self.max_age_in_sec = max_age_in_sec

    def should_refetch(
        self,
        payload: JSONObject,
        user_context: Dict[str, Any],
    ) -> bool:
        max_age_in_sec = self.max_age_in_sec

        # (claim value is None) OR (value has expired)
        return (self.claim.get_value_from_payload(payload, user_context) is None) or (
            (max_age_in_sec is not None)
            and (
                payload[self.claim.key]["t"]
                < (get_timestamp_ms() - max_age_in_sec * 1000)
            )
        )

    async def validate(
        self,
        payload: JSONObject,
        user_context: Dict[str, Any],
    ):
        val = self.val
        max_age_in_sec = self.max_age_in_sec

        claim_val: JSONPrimitive = self.claim.get_value_from_payload(
            payload, user_context
        )
        if claim_val is None:
            return ClaimValidationResult(
                is_valid=False,
                reason={
                    "message": "value does not exist",
                    "expectedValue": val,
                    "actualValue": claim_val,
                },
            )

        if max_age_in_sec is not None:
            assert isinstance(self.claim, PrimitiveClaim)
            last_refetch_time = self.claim.get_last_refetch_time(payload, user_context)
            assert last_refetch_time is not None
            age_in_sec = (get_timestamp_ms() - last_refetch_time) / 1000
            if age_in_sec > max_age_in_sec:
                return ClaimValidationResult(
                    is_valid=False,
                    reason={
                        "message": "expired",
                        "ageInSeconds": age_in_sec,
                        "maxAgeInSeconds": max_age_in_sec,
                    },
                )

        if claim_val != val:
            return ClaimValidationResult(
                is_valid=False,
                reason={
                    "message": "wrong value",
                    "expectedValue": val,
                    "actualValue": claim_val,
                },
            )

        return ClaimValidationResult(is_valid=True)


class PrimitiveClaimValidators(Generic[Primitive]):
    def __init__(
        self,
        claim: SessionClaim[Primitive],
        default_max_age_in_sec: Optional[int],
    ) -> None:
        self.claim = claim
        self.default_max_age_in_sec = default_max_age_in_sec

    def has_value(
        self,
        val: Primitive,
        max_age_in_sec: Optional[int] = None,
        id_: Optional[str] = None,
    ) -> SessionClaimValidator:
        max_age_in_sec = max_age_in_sec or self.default_max_age_in_sec
        return HasValueSCV(
            (id_ or self.claim.key), self.claim, val=val, max_age_in_sec=max_age_in_sec
        )


class PrimitiveClaim(SessionClaim[Primitive]):
    def __init__(
        self,
        key: str,
        fetch_value: Callable[
            [str, str, Dict[str, Any]],
            MaybeAwaitable[Optional[Primitive]],
        ],
        default_max_age_in_sec: Optional[int] = None,
    ) -> None:
        super().__init__(key, fetch_value)

        claim = self
        self.validators = PrimitiveClaimValidators(claim, default_max_age_in_sec)

    def add_to_payload_(
        self,
        payload: Dict[str, Any],
        value: Primitive,
        user_context: Union[Dict[str, Any], None] = None,
    ) -> JSONObject:
        payload[self.key] = {"v": value, "t": get_timestamp_ms()}
        _ = user_context

        return payload

    def remove_from_payload_by_merge_(
        self, payload: JSONObject, user_context: Optional[Dict[str, Any]] = None
    ) -> JSONObject:
        payload[self.key] = None
        return payload

    def remove_from_payload(
        self, payload: JSONObject, user_context: Optional[Dict[str, Any]] = None
    ) -> JSONObject:
        del payload[self.key]
        return payload

    def get_value_from_payload(
        self, payload: JSONObject, user_context: Union[Dict[str, Any], None] = None
    ) -> Union[Primitive, None]:
        _ = user_context

        return payload.get(self.key, {}).get("v")

    def get_last_refetch_time(
        self, payload: JSONObject, user_context: Union[Dict[str, Any], None] = None
    ) -> Union[int, None]:
        _ = user_context

        return payload.get(self.key, {}).get("t")
