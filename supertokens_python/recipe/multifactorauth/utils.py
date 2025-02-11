# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

import math
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.multifactorauth.multi_factor_auth_claim import (
    MultiFactorAuthClaim,
)
from supertokens_python.recipe.multifactorauth.types import (
    FactorIds,
    MFAClaimValue,
    MFARequirementList,
)
from supertokens_python.recipe.multitenancy.asyncio import get_tenant
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import get_session_information
from supertokens_python.recipe.session.exceptions import UnauthorisedError
from supertokens_python.types import RecipeUserId
from supertokens_python.utils import log_debug_message

if TYPE_CHECKING:
    from .types import MultiFactorAuthConfig, OverrideConfig


# IMPORTANT: If this function signature is modified, please update all tha places where this function is called.
# There will be no type errors cause we use importLib to dynamically import if to prevent cyclic import issues.
def validate_and_normalise_user_input(
    first_factors: Optional[List[str]],
    override: Union[OverrideConfig, None] = None,
) -> MultiFactorAuthConfig:
    if first_factors is not None and len(first_factors) == 0:
        raise ValueError("'first_factors' can be either None or a non-empty list")

    from .types import MultiFactorAuthConfig as MFAC
    from .types import OverrideConfig as OC

    if override is None:
        override = OC()

    return MFAC(
        first_factors=first_factors,
        override=override,
    )


class UpdateAndGetMFARelatedInfoInSessionResult:
    def __init__(
        self,
        completed_factors: Dict[str, int],
        mfa_requirements_for_auth: MFARequirementList,
        is_mfa_requirements_for_auth_satisfied: bool,
    ):
        self.completed_factors = completed_factors
        self.mfa_requirements_for_auth = mfa_requirements_for_auth
        self.is_mfa_requirements_for_auth_satisfied = (
            is_mfa_requirements_for_auth_satisfied
        )


# IMPORTANT: If this function signature is modified, please update all tha places where this function is called.
# There will be no type errors cause we use importLib to dynamically import if to prevent cyclic import issues.
async def update_and_get_mfa_related_info_in_session(
    user_context: Dict[str, Any],
    input_session_recipe_user_id: Optional[RecipeUserId] = None,
    input_tenant_id: Optional[str] = None,
    input_access_token_payload: Optional[Dict[str, Any]] = None,
    input_session: Optional[SessionContainer] = None,
    input_updated_factor_id: Optional[str] = None,
) -> UpdateAndGetMFARelatedInfoInSessionResult:
    from supertokens_python.recipe.multifactorauth.recipe import (
        MultiFactorAuthRecipe as Recipe,
    )

    session_recipe_user_id: RecipeUserId
    tenant_id: str
    access_token_payload: Dict[str, Any]
    session_handle: str

    if input_session is not None:
        session_recipe_user_id = input_session.get_recipe_user_id(user_context)
        tenant_id = input_session.get_tenant_id(user_context)
        access_token_payload = input_session.get_access_token_payload(user_context)
        session_handle = input_session.get_handle(user_context)
    else:
        assert input_session_recipe_user_id is not None
        assert input_tenant_id is not None
        assert input_access_token_payload is not None
        session_recipe_user_id = input_session_recipe_user_id
        tenant_id = input_tenant_id
        access_token_payload = input_access_token_payload
        session_handle = access_token_payload["sessionHandle"]

    updated_claim_val = False
    mfa_claim_value = MultiFactorAuthClaim.get_value_from_payload(access_token_payload)

    if input_updated_factor_id is not None:
        if mfa_claim_value is None:
            updated_claim_val = True
            mfa_claim_value = MFAClaimValue(
                c={input_updated_factor_id: math.floor(time.time())},
                v=True,  # updated later in the function
            )
        else:
            updated_claim_val = True
            mfa_claim_value.c[input_updated_factor_id] = math.floor(time.time())

    if mfa_claim_value is None:
        session_user = (
            await AccountLinkingRecipe.get_instance().recipe_implementation.get_user(
                session_recipe_user_id.get_as_string(), user_context
            )
        )
        if session_user is None:
            raise UnauthorisedError("Session user not found")

        session_info = await get_session_information(session_handle, user_context)
        if session_info is None:
            raise UnauthorisedError("Session not found")

        first_factor_time = session_info.time_created
        computed_first_factor_id_for_session = None

        for login_method in session_user.login_methods:
            if (
                login_method.recipe_user_id.get_as_string()
                == session_recipe_user_id.get_as_string()
            ):
                if login_method.recipe_id == "emailpassword":
                    valid_res = await is_valid_first_factor(
                        tenant_id, FactorIds.EMAILPASSWORD, user_context
                    )
                    if valid_res == "TENANT_NOT_FOUND_ERROR":
                        raise UnauthorisedError("Tenant not found")
                    elif valid_res == "OK":
                        computed_first_factor_id_for_session = FactorIds.EMAILPASSWORD
                        break
                elif login_method.recipe_id == "thirdparty":
                    valid_res = await is_valid_first_factor(
                        tenant_id, FactorIds.THIRDPARTY, user_context
                    )
                    if valid_res == "TENANT_NOT_FOUND_ERROR":
                        raise UnauthorisedError("Tenant not found")
                    elif valid_res == "OK":
                        computed_first_factor_id_for_session = FactorIds.THIRDPARTY
                        break
                else:
                    factors_to_check: List[str] = []
                    if login_method.email is not None:
                        factors_to_check.extend(
                            [FactorIds.LINK_EMAIL, FactorIds.OTP_EMAIL]
                        )
                    if login_method.phone_number is not None:
                        factors_to_check.extend(
                            [FactorIds.LINK_PHONE, FactorIds.OTP_PHONE]
                        )

                    for factor_id in factors_to_check:
                        valid_res = await is_valid_first_factor(
                            tenant_id, factor_id, user_context
                        )
                        if valid_res == "TENANT_NOT_FOUND_ERROR":
                            raise UnauthorisedError("Tenant not found")
                        elif valid_res == "OK":
                            computed_first_factor_id_for_session = factor_id
                            break

                    if computed_first_factor_id_for_session is not None:
                        break

        if computed_first_factor_id_for_session is None:
            raise UnauthorisedError("Incorrect login method used")

        updated_claim_val = True
        mfa_claim_value = MFAClaimValue(
            c={computed_first_factor_id_for_session: first_factor_time},
            v=True,  # updated later in this function
        )

    completed_factors = mfa_claim_value.c

    async def user_getter():
        resp = await AccountLinkingRecipe.get_instance().recipe_implementation.get_user(
            session_recipe_user_id.get_as_string(), user_context
        )
        if resp is None:
            raise UnauthorisedError("Session user not found")
        return resp

    async def get_required_secondary_factors_for_tenant(
        tenant_id: str, user_context: Dict[str, Any]
    ) -> List[str]:
        tenant_info = await get_tenant(tenant_id, user_context)
        if tenant_info is None:
            raise UnauthorisedError("Tenant not found")
        return (
            tenant_info.required_secondary_factors
            if tenant_info.required_secondary_factors is not None
            else []
        )

    async def get_factors_setup_for_user() -> List[str]:
        return await Recipe.get_instance_or_throw_error().recipe_implementation.get_factors_setup_for_user(
            user=(await user_getter()), user_context=user_context
        )

    async def get_required_secondary_factors_for_user() -> List[str]:
        return await Recipe.get_instance_or_throw_error().recipe_implementation.get_required_secondary_factors_for_user(
            user_id=(await user_getter()).id, user_context=user_context
        )

    async def get_required_secondary_factors_for_tenant_helper() -> List[str]:
        return await get_required_secondary_factors_for_tenant(
            tenant_id=tenant_id, user_context=user_context
        )

    mfa_requirements_for_auth = await Recipe.get_instance_or_throw_error().recipe_implementation.get_mfa_requirements_for_auth(
        tenant_id=tenant_id,
        access_token_payload=access_token_payload,
        user=user_getter,
        factors_set_up_for_user=get_factors_setup_for_user,
        required_secondary_factors_for_user=get_required_secondary_factors_for_user,
        required_secondary_factors_for_tenant=get_required_secondary_factors_for_tenant_helper,
        completed_factors=completed_factors,
        user_context=user_context,
    )

    are_auth_reqs_complete = (
        len(
            MultiFactorAuthClaim.get_next_set_of_unsatisfied_factors(
                completed_factors, mfa_requirements_for_auth
            ).factor_ids
        )
        == 0
    )

    if mfa_claim_value.v != are_auth_reqs_complete:
        updated_claim_val = True
        mfa_claim_value.v = are_auth_reqs_complete

    if input_session is not None and updated_claim_val:
        await input_session.set_claim_value(
            MultiFactorAuthClaim, mfa_claim_value, user_context
        )

    return UpdateAndGetMFARelatedInfoInSessionResult(
        completed_factors=completed_factors,
        mfa_requirements_for_auth=mfa_requirements_for_auth,
        is_mfa_requirements_for_auth_satisfied=mfa_claim_value.v,
    )


# IMPORTANT: If this function signature is modified, please update all tha places where this function is called.
# There will be no type errors cause we use importLib to dynamically import if to prevent cyclic import issues.
async def is_valid_first_factor(
    tenant_id: str, factor_id: str, user_context: Dict[str, Any]
) -> Literal["OK", "INVALID_FIRST_FACTOR_ERROR", "TENANT_NOT_FOUND_ERROR"]:
    mt_recipe = MultitenancyRecipe.get_instance()
    tenant_info = await get_tenant(tenant_id=tenant_id, user_context=user_context)
    if tenant_info is None:
        return "TENANT_NOT_FOUND_ERROR"

    tenant_config = tenant_info

    first_factors_from_mfa = mt_recipe.static_first_factors

    log_debug_message(
        f"is_valid_first_factor got {', '.join(tenant_config.first_factors) if tenant_config.first_factors else None} from tenant config"
    )
    log_debug_message(f"is_valid_first_factor got {first_factors_from_mfa} from MFA")

    configured_first_factors: Union[List[str], None] = (
        tenant_config.first_factors or first_factors_from_mfa
    )

    if configured_first_factors is None:
        configured_first_factors = mt_recipe.all_available_first_factors

    if is_factor_configured_for_tenant(
        all_available_first_factors=mt_recipe.all_available_first_factors,
        first_factors=configured_first_factors,
        factor_id=factor_id,
    ):
        return "OK"

    return "INVALID_FIRST_FACTOR_ERROR"


def is_factor_configured_for_tenant(
    all_available_first_factors: List[str],
    first_factors: List[str],
    factor_id: str,
) -> bool:
    configured_first_factors = [
        f
        for f in first_factors
        if f in all_available_first_factors or f not in FactorIds.__dict__.values()
    ]

    return factor_id in configured_first_factors
