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


class UpdateTenantCoreConfigOkResult(APIResponse):
    status: Literal["OK"] = "OK"

    def __init__(self):
        self.status = "OK"

    def to_json(self) -> Dict[str, Literal["OK"]]:
        return {"status": self.status}


class UpdateTenantCoreConfigUnknownTenantErrorResult(APIResponse):
    status: Literal["UNKNOWN_TENANT_ERROR"] = "UNKNOWN_TENANT_ERROR"

    def __init__(self):
        self.status = "UNKNOWN_TENANT_ERROR"

    def to_json(self) -> Dict[str, Literal["UNKNOWN_TENANT_ERROR"]]:
        return {"status": self.status}


class UpdateTenantCoreConfigInvalidConfigErrorResult(APIResponse):
    status: Literal["INVALID_CONFIG_ERROR"] = "INVALID_CONFIG_ERROR"

    def __init__(self, message: str):
        self.status = "INVALID_CONFIG_ERROR"
        self.message = message

    def to_json(self) -> Dict[str, Union[Literal["INVALID_CONFIG_ERROR"], str]]:
        return {"status": self.status, "message": self.message}


async def update_tenant_core_config(
    _: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[
    UpdateTenantCoreConfigOkResult,
    UpdateTenantCoreConfigUnknownTenantErrorResult,
    UpdateTenantCoreConfigInvalidConfigErrorResult,
]:
    request_body = await options.request.json()
    if request_body is None:
        raise_bad_input_exception("Request body is required")
    name = request_body["name"]
    value = request_body["value"]

    mt_recipe = MultitenancyRecipe.get_instance()

    tenant_res = await mt_recipe.recipe_implementation.get_tenant(
        tenant_id=tenant_id, user_context=user_context
    )
    if tenant_res is None:
        return UpdateTenantCoreConfigUnknownTenantErrorResult()

    try:
        await mt_recipe.recipe_implementation.create_or_update_tenant(
            tenant_id=tenant_id,
            config=TenantConfigCreateOrUpdate(
                core_config={name: value},
            ),
            user_context=user_context,
        )
    except Exception as err:
        err_msg = str(err)
        if (
            "SuperTokens core threw an error for a " in err_msg
            and "with status code: 400" in err_msg
        ):
            return UpdateTenantCoreConfigInvalidConfigErrorResult(
                message=err_msg.split(" and message: ")[1]
            )
        raise err

    return UpdateTenantCoreConfigOkResult()
