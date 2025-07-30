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
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideableConfig,
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


MultitenancyOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedMultitenancyOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]
InputOverrideConfig = MultitenancyOverrideConfig
"""Deprecated, use `MultitenancyOverrideConfig` instead."""


class MultitenancyOverrideableConfig(BaseOverrideableConfig):
    """Input config properties overrideable using the plugin config overrides"""

    get_allowed_domains_for_tenant_id: Optional[TypeGetAllowedDomainsForTenantId] = None


class MultitenancyConfig(
    MultitenancyOverrideableConfig,
    BaseConfig[RecipeInterface, APIInterface, MultitenancyOverrideableConfig],
):
    def to_overrideable_config(self) -> MultitenancyOverrideableConfig:
        """Create a `MultitenancyOverrideableConfig` from the current config."""
        return MultitenancyOverrideableConfig(**self.model_dump())

    def from_overrideable_config(
        self,
        overrideable_config: MultitenancyOverrideableConfig,
    ) -> "MultitenancyConfig":
        """
        Create a `MultitenancyConfig` from a `MultitenancyOverrideableConfig`.
        Not a classmethod since it needs to be used in a dynamic context within plugins.
        """
        return MultitenancyConfig(
            **overrideable_config.model_dump(),
            override=self.override,
        )


class NormalisedMultitenancyConfig(BaseNormalisedConfig[RecipeInterface, APIInterface]):
    get_allowed_domains_for_tenant_id: Optional[TypeGetAllowedDomainsForTenantId]


def validate_and_normalise_user_input(
    config: MultitenancyConfig,
) -> NormalisedMultitenancyConfig:
    override_config = NormalisedMultitenancyOverrideConfig.from_input_config(
        override_config=config.override
    )

    return NormalisedMultitenancyConfig(
        get_allowed_domains_for_tenant_id=config.get_allowed_domains_for_tenant_id,
        override=override_config,
    )
