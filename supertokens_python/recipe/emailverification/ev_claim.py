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
from typing import Dict, Any

from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.emailverification.interfaces import (
    GetEmailForUserIdOkResult,
    EmailDoesnotExistError,
)
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
    ):
        super().__init__("st-ev-is-verified")
        self.claim: BooleanClaim = claim  # TODO: Should work without specifying type of self.claim (no pyright errors)
        self.has_value_validator = has_value_validator
        self.refetch_time_on_false_in_ms = refetch_time_on_false_in_seconds * 1000

    async def validate(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> ClaimValidationResult:
        return await self.has_value_validator.validate(payload, user_context)

    def should_refetch(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> MaybeAwaitable[bool]:
        value = self.claim.get_value_from_payload(payload, user_context)
        last_refetch_time = self.claim.get_last_refetch_time(payload, user_context)
        assert last_refetch_time is not None
        return (value is None) or (
            value is False
            and last_refetch_time
            < (get_timestamp_ms() - self.refetch_time_on_false_in_ms)
        )


class EmailVerificationClaimValidators(BooleanClaimValidators):
    def is_verified(
        self, refetch_time_on_false_in_seconds: int = 10
    ) -> SessionClaimValidator:
        has_value_res = self.has_value(True, "st-ev-is-verified")
        assert isinstance(self.claim, BooleanClaim)
        return IsVerifiedSCV(
            self.claim, has_value_res, refetch_time_on_false_in_seconds
        )


class EmailVerificationClaimClass(BooleanClaim):
    def __init__(self):
        async def fetch_value(
            user_id: str, user_context: Dict[str, Any]
        ) -> bool:
            recipe = EmailVerificationRecipe.get_instance()
            email_info = await recipe.get_email_for_user_id(user_id, user_context)

            if isinstance(email_info, GetEmailForUserIdOkResult):
                return await recipe.recipe_implementation.is_email_verified(
                    user_id, email_info.email, user_context
                )
            if isinstance(email_info, EmailDoesnotExistError):
                # we consider people without email addresses as validated
                return True
            raise Exception(
                "Should never come here: UNKNOWN_USER_ID or invalid result from get_email_for_user"
            )

        super().__init__("st-ev", fetch_value)

        self.validators = EmailVerificationClaimValidators(claim=self)


EmailVerificationClaim = EmailVerificationClaimClass()
