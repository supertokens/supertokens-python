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

from typing import Awaitable, Callable, Optional, Union

from supertokens_python.exceptions import SuperTokensError
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.types.config import (
    BaseConfig,
    BaseInputConfig,
    BaseInputOverrideConfig,
    BaseOverrideConfig,
)
from supertokens_python.utils import (
    resolve,
)

from .interfaces import (
    APIInterface,
    RecipeInterface,
    TypeGetAllowedDomainsForTenantId,
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


class InputOverrideConfig(BaseInputOverrideConfig[RecipeInterface, APIInterface]): ...


class OverrideConfig(BaseOverrideConfig[RecipeInterface, APIInterface]): ...


class MultitenancyInputConfig(BaseInputConfig[RecipeInterface, APIInterface]):
    get_allowed_domains_for_tenant_id: Optional[TypeGetAllowedDomainsForTenantId] = None


class MultitenancyConfig(BaseConfig[RecipeInterface, APIInterface]):
    get_allowed_domains_for_tenant_id: Optional[TypeGetAllowedDomainsForTenantId]


def validate_and_normalise_user_input(
    input_config: MultitenancyInputConfig,
) -> MultitenancyConfig:
    override_config = OverrideConfig()
    if input_config.override is not None:
        if input_config.override.functions is not None:
            override_config.functions = input_config.override.functions

        if input_config.override.apis is not None:
            override_config.apis = input_config.override.apis

    return MultitenancyConfig(
        get_allowed_domains_for_tenant_id=input_config.get_allowed_domains_for_tenant_id,
        override=override_config,
    )
