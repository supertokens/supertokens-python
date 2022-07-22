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

import time
from typing import Any, Dict, TypeVar, Union, Callable, Optional

from supertokens_python.types import MaybeAwaitable
from ..interfaces import JSONObject, JSONPrimitive, SessionClaim, SessionClaimValidator

_T = TypeVar("_T")


class PrimitiveClaim(SessionClaim[JSONPrimitive]):
    def __init__(
        self,
        key: str,
        fetch_value: Optional[
            Callable[
                [str, Optional[Dict[str, Any]]],
                MaybeAwaitable[Optional[JSONPrimitive]],
            ]
        ] = None,
    ) -> None:
        super().__init__(key)
        if fetch_value is not None:
            self.fetch_value = fetch_value  # type: ignore

        claim = self

        def has_value(
            val: JSONPrimitive, id_: Union[str, None] = None
        ) -> SessionClaimValidator:
            class HasValueSCV(SessionClaimValidator):
                def __init__(self):
                    super().__init__(id_ or claim.key)
                    self.claim = claim

                def should_refetch(
                    self,
                    payload: JSONObject,
                    user_context: Union[Dict[str, Any], None] = None,
                ):
                    return claim.get_value_from_payload(payload, user_context) is None

                async def validate(
                    self,
                    payload: JSONObject,
                    user_context: Union[Dict[str, Any], None] = None,
                ):
                    claim_val = claim.get_value_from_payload(payload, user_context)
                    is_valid = claim_val == val
                    if is_valid:
                        return {"isValid": True}

                    return {
                        "isValid": False,
                        "reason": {
                            "message": "wrong value",
                            "expectedValue": val,
                            "actualValue": claim_val,
                        },
                    }

            scv = HasValueSCV()
            return scv

        def has_fresh_value(
            val: JSONPrimitive, max_age_in_sec: int, id_: Union[str, None] = None
        ) -> SessionClaimValidator:
            class HasFreshValueSCV(SessionClaimValidator):
                def __init__(self):
                    super().__init__(id_ or (claim.key + "-fresh-val"))
                    self.claim = claim

                def should_refetch(
                    self,
                    payload: JSONObject,
                    user_context: Union[Dict[str, Any], None] = None,
                ):
                    # (claim value is None) OR (value has expired)
                    return (
                        claim.get_value_from_payload(payload, user_context) is None
                    ) or (payload[claim.key]["t"] < time.time() - max_age_in_sec * 1000)

                async def validate(
                    self,
                    payload: JSONObject,
                    user_context: Union[Dict[str, Any], None] = None,
                ):
                    claim_val = claim.get_value_from_payload(payload, user_context)
                    if claim_val is None:
                        return {
                            "isValid": False,
                            "reason": {
                                "message": "value does not exist",
                                "expectedValue": val,
                                "actualValue": claim_val,
                            },
                        }

                    age_in_sec = (
                        time.time()
                        - float(claim.get_last_refetch_time(payload, user_context) or 0)
                    ) / 1000
                    if age_in_sec > max_age_in_sec:
                        return {
                            "isValid": False,
                            "reason": {
                                "message": "expired",
                                "ageInSeconds": age_in_sec,
                                "maxAgeInSeconds": max_age_in_sec,
                            },
                        }
                    if claim_val != val:
                        return {
                            "isValid": False,
                            "reason": {
                                "message": "wrong value",
                                "expectedValue": val,
                                "actualValue": claim_val,
                            },
                        }

                    return {"isValid": True}

            scv = HasFreshValueSCV()
            return scv

        class Validators:
            def __init__(self) -> None:
                self.has_value = has_value
                self.has_fresh_value = has_fresh_value

            # def __setattr__(self, k: str, v: Any):
            #     super().__setattr__(k, v)

        self.validators = Validators()

    def add_to_payload_(
        self,
        payload: Any,
        value: JSONPrimitive,
        user_context: Union[Dict[str, Any], None] = None,
    ) -> JSONObject:
        payload[self.key] = {"v": value, "t": time.time()}
        _ = user_context

        return payload

    def remove_from_payload_by_merge_(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> JSONObject:
        _ = user_context

        payload[self.key] = None
        return payload

    def remove_from_payload(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> JSONObject:
        _ = user_context
        del payload[self.key]
        return payload

    def get_value_from_payload(
        self, payload: JSONObject, user_context: Union[Dict[str, Any], None] = None
    ) -> Union[JSONPrimitive, None]:
        _ = user_context
        return payload.get(self.key, {}).get("v")

    def get_last_refetch_time(
        self, payload: JSONObject, user_context: Union[Dict[str, Any], None] = None
    ) -> Union[int, None]:
        _ = user_context
        return payload.get(self.key, {}).get("t")
