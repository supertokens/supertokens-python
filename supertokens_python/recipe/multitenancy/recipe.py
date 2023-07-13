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

from os import environ
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.recipe.session.claim_base_classes.primitive_array_claim import (
    PrimitiveArrayClaim,
)
from supertokens_python.recipe.session.interfaces import JSONObject
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.utils import get_timestamp_ms

from ...post_init_callbacks import PostSTInitCallbacks

from .interfaces import (
    APIInterface,
    APIOptions,
    TypeGetAllowedDomainsForTenantId,
)

from .recipe_implementation import RecipeImplementation

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.supertokens import AppInfo
    from supertokens_python.recipe.thirdparty.provider import ProviderInput

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.types import GeneralErrorResponse

from supertokens_python.recipe.thirdparty.providers.config_utils import (
    find_and_create_provider_instance,
    merge_providers_from_core_and_static,
)
from supertokens_python.recipe.thirdparty.exceptions import ClientTypeNotFoundError

from .api import handle_login_methods_api
from .constants import LOGIN_METHODS
from .exceptions import TenantDoesNotExistError, RecipeDisabledForTenantError
from .interfaces import (
    LoginMethodsGetOkResult,
    ThirdPartyProvider,
    LoginMethodEmailPassword,
    LoginMethodPasswordless,
    LoginMethodThirdParty,
)
from .utils import (
    InputErrorHandlers,
    InputOverrideConfig,
    validate_and_normalise_user_input,
)


class MultitenancyRecipe(RecipeModule):
    recipe_id = "multitenancy"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        get_allowed_domains_for_tenant_id: Optional[
            TypeGetAllowedDomainsForTenantId
        ] = None,
        error_handlers: Union[InputErrorHandlers, None] = None,
        override: Union[InputOverrideConfig, None] = None,
    ) -> None:
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            get_allowed_domains_for_tenant_id,
            error_handlers,
            override,
        )

        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id), self.config
        )
        self.recipe_implementation = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )

        api_implementation = APIImplementation()
        self.api_implementation = (
            api_implementation
            if self.config.override.apis is None
            else self.config.override.apis(api_implementation)
        )

        self.static_third_party_providers: List[ProviderInput] = []
        self.get_allowed_domains_for_tenant_id = (
            self.config.get_allowed_domains_for_tenant_id
        )

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, (TenantDoesNotExistError, RecipeDisabledForTenantError))

    def get_apis_handled(self) -> List[APIHandled]:
        return [
            APIHandled(
                NormalisedURLPath(LOGIN_METHODS),
                "get",
                LOGIN_METHODS,
                self.api_implementation.disable_login_methods_get,
            ),
        ]

    async def handle_api_request(
        self,
        request_id: str,
        tenant_id: Optional[str],
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
    ) -> Union[BaseResponse, None]:
        api_options = APIOptions(
            request,
            response,
            self.recipe_id,
            self.config,
            self.recipe_implementation,
            self.static_third_party_providers,
        )
        return await handle_login_methods_api(
            self.api_implementation,
            api_options,
        )

    async def handle_error(
        self, request: BaseRequest, err: SuperTokensError, response: BaseResponse
    ) -> BaseResponse:
        if isinstance(err, TenantDoesNotExistError):
            return await self.config.error_handlers.on_tenant_does_not_exist(
                err, request, response
            )

        if isinstance(err, RecipeDisabledForTenantError):
            return await self.config.error_handlers.on_recipe_disabled_for_tenant(
                err, request, response
            )

        raise Exception("should never come here")

    def get_all_cors_headers(self) -> List[str]:
        return []

    @staticmethod
    def init(
        get_allowed_domains_for_tenant_id: Union[
            TypeGetAllowedDomainsForTenantId, None
        ] = None,
        error_handlers: Union[InputErrorHandlers, None] = None,
        override: Union[InputOverrideConfig, None] = None,
    ):
        def func(app_info: AppInfo):
            if MultitenancyRecipe.__instance is None:
                MultitenancyRecipe.__instance = MultitenancyRecipe(
                    MultitenancyRecipe.recipe_id,
                    app_info,
                    get_allowed_domains_for_tenant_id,
                    error_handlers,
                    override,
                )

                def callback():
                    pass  # TODO CLAIMS

                PostSTInitCallbacks.add_post_init_callback(callback)

                return MultitenancyRecipe.__instance
            raise_general_exception(
                "Multitenancy recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance() -> MultitenancyRecipe:
        if MultitenancyRecipe.__instance is not None:
            return MultitenancyRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def get_instance_optional() -> Optional[MultitenancyRecipe]:
        return MultitenancyRecipe.__instance

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        MultitenancyRecipe.__instance = None


class APIImplementation(APIInterface):
    async def login_methods_get(
        self,
        tenant_id: Optional[str],
        client_type: Optional[str],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[LoginMethodsGetOkResult, GeneralErrorResponse]:
        tenant_config = await api_options.recipe_implementation.get_tenant(
            tenant_id, user_context
        )

        provider_inputs_from_static = api_options.static_third_party_providers
        provider_configs_from_core = tenant_config.third_party.providers

        merged_providers = merge_providers_from_core_and_static(
            provider_configs_from_core, provider_inputs_from_static
        )

        final_provider_list: List[ThirdPartyProvider] = []

        for provider_input in merged_providers:
            try:
                provider_instance = await find_and_create_provider_instance(
                    merged_providers,
                    provider_input.config.third_party_id,
                    client_type,
                    user_context,
                )
            except ClientTypeNotFoundError:
                continue
            final_provider_list.append(
                ThirdPartyProvider(provider_instance.id, provider_instance.config.name)
            )

        return LoginMethodsGetOkResult(
            LoginMethodEmailPassword(tenant_config.email_password.enabled),
            LoginMethodPasswordless(tenant_config.passwordless.enabled),
            LoginMethodThirdParty(
                tenant_config.third_party.enabled, final_provider_list
            ),
        )


class AllowedDomainsClaimClass(PrimitiveArrayClaim[List[str]]):
    def __init__(self):
        async def fetch_value(_user_id: str, user_context: Dict[str, Any]) -> List[str]:
            recipe = MultitenancyRecipe.get_instance()
            tenant_id = (
                None  # TODO fetch value will be passed with tenant_id as well later
            )

            if recipe.config.get_allowed_domains_for_tenant_id is None:
                return (
                    []
                )  # User did not provide a function to get allowed domains, but is using a validator. So we don't allow any domains by default

            domains_res = await recipe.config.get_allowed_domains_for_tenant_id(
                tenant_id, user_context
            )
            return domains_res

        super().__init__(
            key="st-tenant-domains",
            fetch_value=fetch_value,
            default_max_age_in_sec=3600,
        )

    def get_value_from_payload(
        self, payload: JSONObject, user_context: Union[Dict[str, Any], None] = None
    ) -> Union[List[str], None]:
        if self.key not in payload:
            return []
        return super().get_value_from_payload(payload, user_context)

    def get_last_refetch_time(
        self, payload: JSONObject, user_context: Union[Dict[str, Any], None] = None
    ) -> Union[int, None]:
        if self.key not in payload:
            return get_timestamp_ms()
        return super().get_last_refetch_time(payload, user_context)


AllowedDomainsClaim = AllowedDomainsClaimClass()
