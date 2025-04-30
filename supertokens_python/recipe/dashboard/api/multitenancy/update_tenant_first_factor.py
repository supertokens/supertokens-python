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
from supertokens_python.recipe.multitenancy.interfaces import TenantConfigCreateOrUpdate
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.types.response import APIResponse

from ...interfaces import APIInterface, APIOptions
from .utils import (
    get_factor_not_available_message,
    get_normalised_first_factors_based_on_tenant_config_from_core_and_sdk_init,
)


class UpdateTenantFirstFactorOkResult(APIResponse):
    status: Literal["OK"] = "OK"

    def __init__(self):
        self.status = "OK"

    def to_json(self) -> Dict[str, Literal["OK"]]:
        return {"status": self.status}


class UpdateTenantFirstFactorRecipeNotConfiguredOnBackendSdkErrorResult(APIResponse):
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


class UpdateTenantFirstFactorUnknownTenantErrorResult(APIResponse):
    status: Literal["UNKNOWN_TENANT_ERROR"] = "UNKNOWN_TENANT_ERROR"

    def __init__(self):
        self.status = "UNKNOWN_TENANT_ERROR"

    def to_json(self) -> Dict[str, Literal["UNKNOWN_TENANT_ERROR"]]:
        return {"status": self.status}


async def update_tenant_first_factor(
    _: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[
    UpdateTenantFirstFactorOkResult,
    UpdateTenantFirstFactorRecipeNotConfiguredOnBackendSdkErrorResult,
    UpdateTenantFirstFactorUnknownTenantErrorResult,
]:
    request_body = await options.request.json()
    if request_body is None:
        raise_bad_input_exception("Request body is required")
    factor_id = request_body["factorId"]
    enable = request_body["enable"]

    mt_recipe = MultitenancyRecipe.get_instance()

    if enable is True:
        if factor_id not in mt_recipe.all_available_first_factors:
            return UpdateTenantFirstFactorRecipeNotConfiguredOnBackendSdkErrorResult(
                message=get_factor_not_available_message(
                    factor_id, mt_recipe.all_available_first_factors
                )
            )

    tenant_res = await mt_recipe.recipe_implementation.get_tenant(
        tenant_id=tenant_id, user_context=user_context
    )

    if tenant_res is None:
        return UpdateTenantFirstFactorUnknownTenantErrorResult()

    first_factors = (
        get_normalised_first_factors_based_on_tenant_config_from_core_and_sdk_init(
            tenant_res
        )
    )

    if enable is True:
        if factor_id not in first_factors:
            first_factors.append(factor_id)
    else:
        first_factors = [f for f in first_factors if f != factor_id]

    await mt_recipe.recipe_implementation.create_or_update_tenant(
        tenant_id=tenant_id,
        config=TenantConfigCreateOrUpdate(
            first_factors=first_factors,
        ),
        user_context=user_context,
    )

    return UpdateTenantFirstFactorOkResult()
