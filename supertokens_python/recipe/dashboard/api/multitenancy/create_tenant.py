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

from supertokens_python.exceptions import BadInputError
from supertokens_python.recipe.multitenancy.asyncio import create_or_update_tenant
from supertokens_python.recipe.multitenancy.interfaces import (
    TenantConfigCreateOrUpdate,
)
from supertokens_python.types.response import APIResponse

from ...interfaces import APIInterface, APIOptions


class CreateTenantOkResult(APIResponse):
    def __init__(self, created_new: bool):
        self.status = "OK"
        self.created_new = created_new

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "createdNew": self.created_new}


class CreateTenantMultitenancyNotEnabledError(APIResponse):
    def __init__(self):
        self.status = "MULTITENANCY_NOT_ENABLED_IN_CORE_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class CreateTenantTenantIdAlreadyExistsError(APIResponse):
    def __init__(self):
        self.status = "TENANT_ID_ALREADY_EXISTS_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class CreateTenantInvalidTenantIdError(APIResponse):
    def __init__(self, message: str):
        self.status = "INVALID_TENANT_ID_ERROR"
        self.message = message

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "message": self.message}


async def create_tenant(
    _: APIInterface,
    __: str,
    options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[
    CreateTenantOkResult,
    CreateTenantMultitenancyNotEnabledError,
    CreateTenantTenantIdAlreadyExistsError,
    CreateTenantInvalidTenantIdError,
]:
    request_body = await options.request.json()
    if request_body is None:
        raise BadInputError("Request body is required")
    tenant_id = request_body.get("tenantId")
    config = {k: v for k, v in request_body.items() if k != "tenantId"}

    if not isinstance(tenant_id, str) or tenant_id == "":
        raise BadInputError("Missing required parameter 'tenantId'")

    try:
        tenant_res = await create_or_update_tenant(
            tenant_id, TenantConfigCreateOrUpdate.from_json(config), user_context
        )
    except Exception as err:
        err_msg: str = str(err)
        if "SuperTokens core threw an error for a " in err_msg:
            if "with status code: 402" in err_msg:
                return CreateTenantMultitenancyNotEnabledError()
            if "with status code: 400" in err_msg:
                return CreateTenantInvalidTenantIdError(
                    err_msg.split(" and message: ")[1]
                )
        raise err

    if not tenant_res.created_new:
        return CreateTenantTenantIdAlreadyExistsError()

    return CreateTenantOkResult(tenant_res.created_new)
