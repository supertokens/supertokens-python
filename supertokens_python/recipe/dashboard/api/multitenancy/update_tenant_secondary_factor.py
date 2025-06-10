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

from typing import Any, Dict, Union

from typing_extensions import Literal

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.multifactorauth.recipe import MultiFactorAuthRecipe
from supertokens_python.recipe.multitenancy.interfaces import TenantConfigCreateOrUpdate
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.types.response import APIResponse

from ...interfaces import APIInterface, APIOptions
from .utils import (
    get_factor_not_available_message,
    get_normalised_required_secondary_factors_based_on_tenant_config_from_core_and_sdk_init,
)


class UpdateTenantSecondaryFactorOkResult(APIResponse):
    status: Literal["OK"] = "OK"
    is_mfa_requirements_for_auth_overridden: bool

    def __init__(self, is_mfa_requirements_for_auth_overridden: bool):
        self.status = "OK"
        self.is_mfa_requirements_for_auth_overridden = (
            is_mfa_requirements_for_auth_overridden
        )

    def to_json(self) -> Dict[str, Union[Literal["OK"], bool]]:
        return {
            "status": self.status,
            "isMFARequirementsForAuthOverridden": self.is_mfa_requirements_for_auth_overridden,
        }


class UpdateTenantSecondaryFactorRecipeNotConfiguredOnBackendSdkErrorResult(
    APIResponse
):
    status: Literal["RECIPE_NOT_CONFIGURED_ON_BACKEND_SDK_ERROR"] = (
        "RECIPE_NOT_CONFIGURED_ON_BACKEND_SDK_ERROR"
    )

    def __init__(self, message: str):
        self.status = "RECIPE_NOT_CONFIGURED_ON_BACKEND_SDK_ERROR"
        self.message = message

    def to_json(
        self,
    ) -> Dict[str, Union[Literal["RECIPE_NOT_CONFIGURED_ON_BACKEND_SDK_ERROR"], str]]:
        return {"status": self.status, "message": self.message}


class UpdateTenantSecondaryFactorMfaNotInitializedErrorResult(APIResponse):
    status: Literal["MFA_NOT_INITIALIZED_ERROR"] = "MFA_NOT_INITIALIZED_ERROR"

    def __init__(self):
        self.status = "MFA_NOT_INITIALIZED_ERROR"

    def to_json(self) -> Dict[str, Literal["MFA_NOT_INITIALIZED_ERROR"]]:
        return {"status": self.status}


class UpdateTenantSecondaryFactorUnknownTenantErrorResult(APIResponse):
    status: Literal["UNKNOWN_TENANT_ERROR"] = "UNKNOWN_TENANT_ERROR"

    def __init__(self):
        self.status = "UNKNOWN_TENANT_ERROR"

    def to_json(self) -> Dict[str, Literal["UNKNOWN_TENANT_ERROR"]]:
        return {"status": self.status}


async def update_tenant_secondary_factor(
    _: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[
    UpdateTenantSecondaryFactorOkResult,
    UpdateTenantSecondaryFactorRecipeNotConfiguredOnBackendSdkErrorResult,
    UpdateTenantSecondaryFactorMfaNotInitializedErrorResult,
    UpdateTenantSecondaryFactorUnknownTenantErrorResult,
]:
    request_body = await options.request.json()
    if request_body is None:
        raise_bad_input_exception("Request body is required")
    factor_id = request_body["factorId"]
    enable = request_body["enable"]

    mt_recipe = MultitenancyRecipe.get_instance()
    mfa_instance = MultiFactorAuthRecipe.get_instance()

    if mfa_instance is None:
        return UpdateTenantSecondaryFactorMfaNotInitializedErrorResult()

    tenant_res = await mt_recipe.recipe_implementation.get_tenant(
        tenant_id=tenant_id, user_context=user_context
    )

    if tenant_res is None:
        return UpdateTenantSecondaryFactorUnknownTenantErrorResult()

    if enable is True:
        all_available_secondary_factors = (
            await mfa_instance.get_all_available_secondary_factor_ids(tenant_res)
        )

        if factor_id not in all_available_secondary_factors:
            return (
                UpdateTenantSecondaryFactorRecipeNotConfiguredOnBackendSdkErrorResult(
                    message=get_factor_not_available_message(
                        factor_id, all_available_secondary_factors
                    )
                )
            )

    secondary_factors = await get_normalised_required_secondary_factors_based_on_tenant_config_from_core_and_sdk_init(
        tenant_res
    )

    if enable is True:
        if factor_id not in secondary_factors:
            secondary_factors.append(factor_id)
    else:
        secondary_factors = [f for f in secondary_factors if f != factor_id]

    await mt_recipe.recipe_implementation.create_or_update_tenant(
        tenant_id=tenant_id,
        config=TenantConfigCreateOrUpdate(
            required_secondary_factors=secondary_factors if secondary_factors else None,
        ),
        user_context=user_context,
    )

    return UpdateTenantSecondaryFactorOkResult(
        is_mfa_requirements_for_auth_overridden=mfa_instance.is_get_mfa_requirements_for_auth_overridden
    )
