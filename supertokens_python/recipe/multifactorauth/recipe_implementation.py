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

import importlib
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Set

from supertokens_python.recipe.multifactorauth.multi_factor_auth_claim import (
    MultiFactorAuthClaim,
    MultiFactorAuthClaimClass,
)
from supertokens_python.recipe.multifactorauth.types import (
    MFAClaimValue,
    MFARequirementList,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.interfaces import (
    ClaimValidationResult,
    JSONObject,
    SessionClaimValidator,
)
from supertokens_python.recipe.usermetadata.asyncio import (
    get_user_metadata,
    update_user_metadata,
)
from supertokens_python.types import User

from .interfaces import RecipeInterface

if TYPE_CHECKING:
    from supertokens_python.querier import Querier

    from .recipe import MultiFactorAuthRecipe


class Validator(SessionClaimValidator):
    def __init__(
        self,
        id_: str,
        claim: MultiFactorAuthClaimClass,
        mfa_requirement_for_auth: Callable[[], Awaitable[MFARequirementList]],
        factors_set_up_for_user: Callable[[], Awaitable[List[str]]],
        factor_id: str,
    ):
        super().__init__(id_)
        self.claim = claim
        self.factors_set_up_for_user = factors_set_up_for_user
        self.factor_id = factor_id
        self.mfa_requirement_for_auth = mfa_requirement_for_auth

    def should_refetch(
        self, payload: Dict[str, Any], user_context: Dict[str, Any]
    ) -> bool:
        if self.claim is None:
            raise Exception("should never happen")

        return self.claim.get_value_from_payload(payload) is None

    async def validate(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> ClaimValidationResult:
        if self.claim is None:
            raise Exception("should never happen")

        if not isinstance(self.claim, MultiFactorAuthClaimClass):
            raise Exception("should never happen")

        claim_val: MFAClaimValue | None = self.claim.get_value_from_payload(payload)

        if claim_val is None:
            raise Exception(
                "This should never happen, claim value not present in payload"
            )

        if claim_val.v:
            # Session already satisfied auth requirements
            return ClaimValidationResult(is_valid=True)

        set_of_unsatisfied_factors = self.claim.get_next_set_of_unsatisfied_factors(
            claim_val.c, await self.mfa_requirement_for_auth()
        )

        factors_set_up_for_user = await self.factors_set_up_for_user()

        if any(
            factor_id in factors_set_up_for_user
            for factor_id in set_of_unsatisfied_factors.factor_ids
        ):
            return ClaimValidationResult(
                is_valid=False,
                reason={
                    "message": "Completed factors in the session does not satisfy the MFA requirements for auth",
                },
            )

        if (
            set_of_unsatisfied_factors.factor_ids
            and self.factor_id not in set_of_unsatisfied_factors.factor_ids
        ):
            return ClaimValidationResult(
                is_valid=False,
                reason={
                    "message": "Not allowed to setup factor that is not in the next set of unsatisfied factors",
                },
            )

        return ClaimValidationResult(is_valid=True)


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        querier: Querier,
        recipe_instance: MultiFactorAuthRecipe,
    ):
        super().__init__()
        self.querier = querier
        self.recipe_instance = recipe_instance

    async def get_factors_setup_for_user(
        self, user: User, user_context: Dict[str, Any]
    ) -> List[str]:
        factor_ids: List[str] = []
        for (
            func
        ) in self.recipe_instance.get_factors_setup_for_user_from_other_recipes_funcs:
            result = await func.func(user, user_context)
            for factor_id in result:
                if factor_id not in factor_ids:
                    factor_ids.append(factor_id)
        return factor_ids

    async def get_mfa_requirements_for_auth(
        self,
        tenant_id: str,
        access_token_payload: Dict[str, Any],
        completed_factors: Dict[str, int],
        user: Callable[[], Awaitable[User]],
        factors_set_up_for_user: Callable[[], Awaitable[List[str]]],
        required_secondary_factors_for_user: Callable[[], Awaitable[List[str]]],
        required_secondary_factors_for_tenant: Callable[[], Awaitable[List[str]]],
        user_context: Dict[str, Any],
    ) -> MFARequirementList:
        all_factors: Set[str] = set()
        for factor in await required_secondary_factors_for_user():
            all_factors.add(factor)
        for factor in await required_secondary_factors_for_tenant():
            all_factors.add(factor)
        return [{"oneOf": list(all_factors)}]

    async def assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
        self,
        session: SessionContainer,
        factor_id: str,
        mfa_requirements_for_auth: Callable[[], Awaitable[MFARequirementList]],
        factors_set_up_for_user: Callable[[], Awaitable[List[str]]],
        user_context: Dict[str, Any],
    ):
        await session.assert_claims(
            [
                Validator(
                    id_=MultiFactorAuthClaim.key,
                    claim=MultiFactorAuthClaim,
                    mfa_requirement_for_auth=mfa_requirements_for_auth,
                    factors_set_up_for_user=factors_set_up_for_user,
                    factor_id=factor_id,
                )
            ],
            user_context,
        )

    async def mark_factor_as_complete_in_session(
        self, session: SessionContainer, factor_id: str, user_context: Dict[str, Any]
    ):
        module = importlib.import_module(
            "supertokens_python.recipe.multifactorauth.utils"
        )

        await module.update_and_get_mfa_related_info_in_session(
            input_session=session,
            input_updated_factor_id=factor_id,
            user_context=user_context,
        )

    async def get_required_secondary_factors_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> List[str]:
        metadata = await get_user_metadata(user_id, user_context)
        result: List[str] = metadata.metadata.get("_supertokens", {}).get(
            "requiredSecondaryFactors", []
        )
        return result

    async def add_to_required_secondary_factors_for_user(
        self, user_id: str, factor_id: str, user_context: Dict[str, Any]
    ):
        metadata = await get_user_metadata(user_id, user_context)
        factor_ids: List[str] = metadata.metadata.get("_supertokens", {}).get(
            "requiredSecondaryFactors", []
        )
        if factor_id not in factor_ids:
            factor_ids.append(factor_id)
            metadata_update = {
                **metadata.metadata,
                "_supertokens": {
                    **metadata.metadata.get("_supertokens", {}),
                    "requiredSecondaryFactors": factor_ids,
                },
            }
            await update_user_metadata(user_id, metadata_update, user_context)

    async def remove_from_required_secondary_factors_for_user(
        self, user_id: str, factor_id: str, user_context: Dict[str, Any]
    ):
        metadata = await get_user_metadata(user_id, user_context)
        factor_ids: List[str] = metadata.metadata.get("_supertokens", {}).get(
            "requiredSecondaryFactors", []
        )
        if factor_id in factor_ids:
            factor_ids = [id for id in factor_ids if id != factor_id]
            metadata_update = {
                **metadata.metadata,
                "_supertokens": {
                    **metadata.metadata.get("_supertokens", {}),
                    "requiredSecondaryFactors": factor_ids,
                },
            }
            await update_user_metadata(user_id, metadata_update, user_context)
