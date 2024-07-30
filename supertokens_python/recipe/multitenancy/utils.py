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

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional

from supertokens_python.exceptions import SuperTokensError
from supertokens_python.framework import BaseRequest, BaseResponse
from supertokens_python.recipe.multifactorauth.types import FactorIds
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.multitenancy.types import TenantConfig
from supertokens_python.utils import log_debug_message, resolve

if TYPE_CHECKING:
    from typing import Union

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


async def is_valid_first_factor(
    tenant_id: str, factor_id: str, user_context: Dict[str, Any]
) -> Dict[str, str]:
    mt_recipe = MultitenancyRecipe.get_instance()
    if mt_recipe is None:
        raise Exception("Should never happen")

    tenant_info = await mt_recipe.recipe_implementation.get_tenant(
        tenant_id=tenant_id, user_context=user_context
    )
    if tenant_info is None:
        return {"status": "TENANT_NOT_FOUND_ERROR"}

    tenant_config: TenantConfig = {
        k: v for k, v in tenant_info.items() if k != "status"
    }

    first_factors_from_mfa = mt_recipe.static_first_factors

    log_debug_message(
        f"is_valid_first_factor got {', '.join(tenant_config.get('first_factors', []))} from tenant config"
    )
    log_debug_message(f"is_valid_first_factor got {first_factors_from_mfa} from MFA")
    log_debug_message(
        f"is_valid_first_factor tenantconfig enables: {[k for k, v in tenant_config.items() if isinstance(v, dict) and v.get('enabled')]}"
    )

    configured_first_factors: Union[List[str], None] = tenant_config.get(
        "first_factors", first_factors_from_mfa
    )

    if configured_first_factors is None:
        configured_first_factors = mt_recipe.all_available_first_factors

    if is_factor_configured_for_tenant(
        tenant_config=tenant_config,
        all_available_first_factors=mt_recipe.all_available_first_factors,
        first_factors=configured_first_factors,
        factor_id=factor_id,
    ):
        return {"status": "OK"}

    return {"status": "INVALID_FIRST_FACTOR_ERROR"}


def is_factor_configured_for_tenant(
    tenant_config: TenantConfig,
    all_available_first_factors: List[str],
    first_factors: List[str],
    factor_id: str,
) -> bool:
    configured_first_factors = [
        f
        for f in first_factors
        if f in all_available_first_factors or f not in FactorIds.__members__.values()
    ]

    return factor_id in configured_first_factors
