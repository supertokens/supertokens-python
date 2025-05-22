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

import importlib
from typing import Any, Dict, List, Union

from supertokens_python.asyncio import get_user
from supertokens_python.recipe.multifactorauth.multi_factor_auth_claim import (
    MultiFactorAuthClaim,
)
from supertokens_python.recipe.multitenancy.asyncio import get_tenant
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.exceptions import (
    InvalidClaimsError,
    SuperTokensSessionError,
    UnauthorisedError,
)
from supertokens_python.types.response import GeneralErrorResponse

from ..interfaces import (
    APIInterface,
    APIOptions,
    NextFactors,
    ResyncSessionAndFetchMFAInfoPUTOkResult,
)


class APIImplementation(APIInterface):
    async def resync_session_and_fetch_mfa_info_put(
        self,
        api_options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[ResyncSessionAndFetchMFAInfoPUTOkResult, GeneralErrorResponse]:
        module = importlib.import_module(
            "supertokens_python.recipe.multifactorauth.utils"
        )

        session_user = await get_user(session.get_user_id(), user_context)

        if session_user is None:
            raise UnauthorisedError(
                "Session user not found",
            )

        mfa_info = await module.update_and_get_mfa_related_info_in_session(
            input_session=session,
            user_context=user_context,
        )
        factors_setup_for_user = (
            await api_options.recipe_implementation.get_factors_setup_for_user(
                user=session_user,
                user_context=user_context,
            )
        )
        tenant_info = await get_tenant(
            session.get_tenant_id(user_context), user_context
        )
        if tenant_info is None:
            raise UnauthorisedError(
                "Tenant not found",
            )
        all_available_secondary_factors = (
            await api_options.recipe_instance.get_all_available_secondary_factor_ids(
                tenant_info
            )
        )

        factors_allowed_to_setup: List[str] = []

        async def get_factors_set_up_for_user():
            return factors_setup_for_user

        async def get_mfa_requirements_for_auth():
            return mfa_info.mfa_requirements_for_auth

        for factor_id in all_available_secondary_factors:
            try:
                await api_options.recipe_implementation.assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
                    session=session,
                    factor_id=factor_id,
                    factors_set_up_for_user=get_factors_set_up_for_user,
                    mfa_requirements_for_auth=get_mfa_requirements_for_auth,
                    user_context=user_context,
                )
                factors_allowed_to_setup.append(factor_id)
            except SuperTokensSessionError as err:
                if not isinstance(err, InvalidClaimsError):
                    raise err

        next_set_of_unsatisfied_factors = (
            MultiFactorAuthClaim.get_next_set_of_unsatisfied_factors(
                mfa_info.completed_factors, mfa_info.mfa_requirements_for_auth
            )
        )

        get_emails_for_factors_result = (
            await api_options.recipe_instance.get_emails_for_factors(
                session_user, session.get_recipe_user_id(user_context)
            )
        )
        get_phone_numbers_for_factors_result = (
            await api_options.recipe_instance.get_phone_numbers_for_factors(
                session_user, session.get_recipe_user_id(user_context)
            )
        )
        if (
            get_emails_for_factors_result.status == "UNKNOWN_SESSION_RECIPE_USER_ID"
            or get_phone_numbers_for_factors_result.status
            == "UNKNOWN_SESSION_RECIPE_USER_ID"
        ):
            raise UnauthorisedError(
                "User no longer associated with the session",
            )

        next_factors = [
            factor_id
            for factor_id in next_set_of_unsatisfied_factors.factor_ids
            if factor_id in factors_allowed_to_setup
            or factor_id in factors_setup_for_user
        ]

        if (
            len(next_factors) == 0
            and len(next_set_of_unsatisfied_factors.factor_ids) != 0
        ):
            raise Exception(
                f"The user is required to complete secondary factors they are not allowed to "
                f"({', '.join(next_set_of_unsatisfied_factors.factor_ids)}), likely because of configuration issues."
            )
        return ResyncSessionAndFetchMFAInfoPUTOkResult(
            factors=NextFactors(
                next_=next_factors,
                already_setup=factors_setup_for_user,
                allowed_to_setup=factors_allowed_to_setup,
            ),
            emails=get_emails_for_factors_result.factor_id_to_emails_map,
            phone_numbers=get_phone_numbers_for_factors_result.factor_id_to_phone_number_map,
        )
