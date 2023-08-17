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

from typing import Any, Dict, Optional, Union, List

from supertokens_python.recipe.multitenancy.interfaces import (
    APIOptions,
    LoginMethodsGetOkResult,
    LoginMethodEmailPassword,
    LoginMethodPasswordless,
    LoginMethodThirdParty,
)
from supertokens_python.types import GeneralErrorResponse

from ..interfaces import APIInterface, ThirdPartyProvider


class APIImplementation(APIInterface):
    async def login_methods_get(
        self,
        tenant_id: str,
        client_type: Optional[str],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[LoginMethodsGetOkResult, GeneralErrorResponse]:
        from supertokens_python.recipe.thirdparty.providers.config_utils import (
            merge_providers_from_core_and_static,
            find_and_create_provider_instance,
        )

        from supertokens_python.recipe.thirdparty.exceptions import (
            ClientTypeNotFoundError,
        )

        tenant_config = await api_options.recipe_implementation.get_tenant(
            tenant_id, user_context
        )

        if tenant_config is None:
            raise Exception("Tenant not found")

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

                if provider_instance is None:
                    raise Exception("Should never come here")

            except ClientTypeNotFoundError:
                continue
            final_provider_list.append(
                ThirdPartyProvider(provider_instance.id, provider_instance.config.name)
            )

        return LoginMethodsGetOkResult(
            email_password=LoginMethodEmailPassword(
                tenant_config.emailpassword.enabled
            ),
            passwordless=LoginMethodPasswordless(tenant_config.passwordless.enabled),
            third_party=LoginMethodThirdParty(
                tenant_config.third_party.enabled, final_provider_list
            ),
        )
