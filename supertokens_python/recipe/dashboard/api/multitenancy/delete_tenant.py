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

from supertokens_python.recipe.multitenancy.asyncio import delete_tenant
from supertokens_python.types.response import APIResponse

from ...interfaces import APIInterface, APIOptions


class DeleteTenantOkResult(APIResponse):
    def __init__(self, did_exist: bool):
        self.status: Literal["OK"] = "OK"
        self.did_exist = did_exist

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "didExist": self.did_exist}


class DeleteTenantCannotDeletePublicTenantError(APIResponse):
    def __init__(self):
        self.status: Literal["CANNOT_DELETE_PUBLIC_TENANT_ERROR"] = (
            "CANNOT_DELETE_PUBLIC_TENANT_ERROR"
        )

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


async def delete_tenant_api(
    _: APIInterface,
    tenant_id: str,
    __: APIOptions,
    user_context: Dict[str, Any],
) -> Union[DeleteTenantOkResult, DeleteTenantCannotDeletePublicTenantError]:
    try:
        delete_tenant_res = await delete_tenant(tenant_id, user_context)
        return DeleteTenantOkResult(delete_tenant_res.did_exist)
    except Exception as err:
        err_msg: str = str(err)
        if (
            "SuperTokens core threw an error for a " in err_msg
            and "with status code: 403" in err_msg
        ):
            return DeleteTenantCannotDeletePublicTenantError()
        raise err
