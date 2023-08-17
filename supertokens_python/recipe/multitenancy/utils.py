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

from typing import TYPE_CHECKING, Awaitable, Optional, Callable
from supertokens_python.exceptions import SuperTokensError
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.utils import (
    resolve,
)

if TYPE_CHECKING:
    from typing import Union
    from .interfaces import (
        TypeGetAllowedDomainsForTenantId,
        RecipeInterface,
        APIInterface,
    )


class ErrorHandlers:
    def __init__(
        self,
        on_tenant_does_not_exist: Callable[
            [SuperTokensError, BaseRequest, BaseResponse],
            Union[BaseResponse, Awaitable[BaseResponse]],
        ],
        on_recipe_disabled_for_tenant: Callable[
            [SuperTokensError, BaseRequest, BaseResponse],
            Union[BaseResponse, Awaitable[BaseResponse]],
        ],
    ):
        self.__on_tenant_does_not_exist = on_tenant_does_not_exist
        self.__on_recipe_disabled_for_tenant = on_recipe_disabled_for_tenant

    async def on_tenant_does_not_exist(
        self,
        err: SuperTokensError,
        request: BaseRequest,
        response: BaseResponse,
    ) -> BaseResponse:
        return await resolve(self.__on_tenant_does_not_exist(err, request, response))

    async def on_recipe_disabled_for_tenant(
        self, err: SuperTokensError, request: BaseRequest, response: BaseResponse
    ) -> BaseResponse:
        return await resolve(
            self.__on_recipe_disabled_for_tenant(err, request, response)
        )


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class MultitenancyConfig:
    def __init__(
        self,
        get_allowed_domains_for_tenant_id: Optional[TypeGetAllowedDomainsForTenantId],
        override: OverrideConfig,
    ):
        self.get_allowed_domains_for_tenant_id = get_allowed_domains_for_tenant_id
        self.override = override


def validate_and_normalise_user_input(
    get_allowed_domains_for_tenant_id: Optional[TypeGetAllowedDomainsForTenantId],
    override: Union[InputOverrideConfig, None] = None,
) -> MultitenancyConfig:
    if override is not None and not isinstance(override, OverrideConfig):  # type: ignore
        raise ValueError("override must be of type OverrideConfig or None")

    if override is None:
        override = InputOverrideConfig()

    return MultitenancyConfig(
        get_allowed_domains_for_tenant_id,
        OverrideConfig(override.functions, override.apis),
    )
