# Copyright (c) 2023, VRAI Labs and/or its affiliates. All rights reserved.
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

import importlib
from typing import Any, Dict, List, Optional, Union

from supertokens_python.recipe.multitenancy.interfaces import (
    APIOptions,
    LoginMethodEmailPassword,
    LoginMethodPasswordless,
    LoginMethodsGetOkResult,
    LoginMethodThirdParty,
)
from supertokens_python.types.response import GeneralErrorResponse

from ..constants import DEFAULT_TENANT_ID
from ..interfaces import APIInterface, ThirdPartyProvider


class APIImplementation(APIInterface):
    async def login_methods_get(
        self,
        tenant_id: str,
        client_type: Optional[str],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[LoginMethodsGetOkResult, GeneralErrorResponse]:
        module = importlib.import_module(
            "supertokens_python.recipe.multifactorauth.utils"
        )
        from supertokens_python.recipe.thirdparty.exceptions import (
            ClientTypeNotFoundError,
        )
        from supertokens_python.recipe.thirdparty.providers.config_utils import (
            find_and_create_provider_instance,
            merge_providers_from_core_and_static,
        )

        tenant_config = await api_options.recipe_implementation.get_tenant(
            tenant_id, user_context
        )

        if tenant_config is None:
            raise Exception("Tenant not found")

        provider_inputs_from_static = api_options.static_third_party_providers
        provider_configs_from_core = tenant_config.third_party_providers

        merged_providers = merge_providers_from_core_and_static(
            provider_configs_from_core,
            provider_inputs_from_static,
            tenant_id == DEFAULT_TENANT_ID,
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

                if provider_instance is None:
                    raise Exception("Should never come here")

            except ClientTypeNotFoundError:
                continue
            final_provider_list.append(
                ThirdPartyProvider(provider_instance.id, provider_instance.config.name)
            )

        first_factors: List[str] = []
        if tenant_config.first_factors is not None:
            first_factors = tenant_config.first_factors
        elif api_options.static_first_factors is not None:
            first_factors = api_options.static_first_factors
        else:
            first_factors = list(set(api_options.all_available_first_factors))

        valid_first_factors: List[str] = []
        for factor_id in first_factors:
            valid_res = await module.is_valid_first_factor(
                tenant_id, factor_id, user_context
            )
            if valid_res == "OK":
                valid_first_factors.append(factor_id)
            if valid_res == "TENANT_NOT_FOUND_ERROR":
                raise Exception("Tenant not found")

        return LoginMethodsGetOkResult(
            email_password=LoginMethodEmailPassword(
                enabled="emailpassword" in valid_first_factors
            ),
            passwordless=LoginMethodPasswordless(
                enabled=any(
                    factor in valid_first_factors
                    for factor in ["otp-email", "otp-phone", "link-email", "link-phone"]
                )
            ),
            third_party=LoginMethodThirdParty(
                enabled="thirdparty" in valid_first_factors,
                providers=final_provider_list,
            ),
            first_factors=valid_first_factors,
        )
