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
from __future__ import annotations
from typing import Dict, Any, Optional

from supertokens_python.recipe.session.claim_base_classes.boolean_claim import (
    BooleanClaim,
    BooleanClaimValidators,
)
from supertokens_python.recipe.session.interfaces import (
    SessionClaimValidator,
    JSONObject,
    ClaimValidationResult,
)
from supertokens_python.types import MaybeAwaitable
from supertokens_python.utils import get_timestamp_ms


class IsVerifiedSCV(SessionClaimValidator):
    def __init__(
        self,
        claim: BooleanClaim,
        has_value_validator: SessionClaimValidator,
        refetch_time_on_false_in_seconds: int,
        max_age_in_seconds: int,
    ):
        super().__init__("st-ev-is-verified")
        self.claim: BooleanClaim = claim  # TODO: Should work without specifying type of self.claim (no pyright errors)
        self.has_value_validator = has_value_validator
        self.refetch_time_on_false_in_ms = refetch_time_on_false_in_seconds * 1000
        self.max_age_in_ms = max_age_in_seconds * 1000

    async def validate(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> ClaimValidationResult:
        return await self.has_value_validator.validate(payload, user_context)

    def should_refetch(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> MaybeAwaitable[bool]:
        value = self.claim.get_value_from_payload(payload, user_context)
        if value is None:
            return True

        last_refetch_time = self.claim.get_last_refetch_time(payload, user_context)
        assert last_refetch_time is not None

        return (last_refetch_time < get_timestamp_ms() - self.max_age_in_ms) or (
            value is False
            and last_refetch_time
            < (get_timestamp_ms() - self.refetch_time_on_false_in_ms)
        )


class EmailVerificationClaimValidators(BooleanClaimValidators):
    def is_verified(
        self,
        refetch_time_on_false_in_seconds: int = 10,
        max_age_in_seconds: Optional[int] = None,  # FIXME:
    ) -> SessionClaimValidator:
        max_age_in_seconds = max_age_in_seconds or self.default_max_age_in_sec

        has_value_res = self.has_value(True, id_="st-ev-is-verified")
        assert isinstance(self.claim, BooleanClaim)
        return IsVerifiedSCV(
            self.claim,
            has_value_res,
            refetch_time_on_false_in_seconds,
            max_age_in_seconds,
        )
