# Copyright (c) 2026, VRAI Labs and/or its affiliates. All rights reserved.
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
from typing import List, Optional, Tuple

from pytest import mark
from supertokens_python import init
from supertokens_python.recipe import multitenancy, session, thirdparty
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
    create_or_update_third_party_config,
)
from supertokens_python.recipe.multitenancy.interfaces import (
    TenantConfigCreateOrUpdate,
)
from supertokens_python.recipe.thirdparty.asyncio import get_provider
from supertokens_python.recipe.thirdparty.provider import (
    ProviderClientConfig,
    ProviderConfig,
    ProviderInput,
    UserFields,
    UserInfoMap,
)
from supertokens_python.recipe.thirdparty.providers.config_utils import (
    merge_config,
)
from supertokens_python.recipe.thirdparty.recipe import ThirdPartyRecipe

from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

THIRD_PARTY_ID = "custom-oidc"

# (from_id_token_payload.user_id, from_id_token_payload.email,
#  from_id_token_payload.email_verified, from_user_info_api.email)
Mapping = Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]

DEFAULT_MAPPING: Mapping = ("sub", "email", "email_verified", "email")
TENANT_MAPPING: Mapping = ("preferred_username", "name", "custom_verified", "name")


def static_custom_provider() -> ProviderInput:
    return ProviderInput(
        config=ProviderConfig(
            third_party_id=THIRD_PARTY_ID,
            clients=[ProviderClientConfig(client_id="public-client")],
            authorization_endpoint="https://idp.example.com/authorize",
            token_endpoint="https://idp.example.com/token",
            user_info_endpoint="https://idp.example.com/userinfo",
        )
    )


async def init_with_tenant_mapping():
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(),
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=[static_custom_provider()]
                    )
                ),
                multitenancy.init(),
            ],
        )
    )

    await create_or_update_tenant(
        "t1", TenantConfigCreateOrUpdate(first_factors=["thirdparty"])
    )
    await create_or_update_third_party_config(
        "t1",
        ProviderConfig(
            third_party_id=THIRD_PARTY_ID,
            clients=[ProviderClientConfig(client_id="t1-client")],
            user_info_map=UserInfoMap(
                from_id_token_payload=UserFields(
                    user_id="preferred_username",
                    email="name",
                    email_verified="custom_verified",
                ),
                from_user_info_api=UserFields(email="name"),
            ),
        ),
    )


async def get_mapping(tenant_id: str) -> Mapping:
    provider = await get_provider(tenant_id, THIRD_PARTY_ID)
    assert provider is not None
    user_info_map = provider.config.user_info_map
    assert user_info_map is not None
    assert user_info_map.from_id_token_payload is not None
    assert user_info_map.from_user_info_api is not None
    return (
        user_info_map.from_id_token_payload.user_id,
        user_info_map.from_id_token_payload.email,
        user_info_map.from_id_token_payload.email_verified,
        user_info_map.from_user_info_api.email,
    )


@mark.parametrize(
    "order",
    [
        ["public", "t1", "public", "t1", "public"],
        ["t1", "public", "t1", "t1", "public", "public", "t1"],
    ],
)
async def test_tenant_user_info_map_does_not_change_other_tenants_mapping(
    order: List[str],
):
    await init_with_tenant_mapping()

    for tenant_id in order:
        expected = TENANT_MAPPING if tenant_id == "t1" else DEFAULT_MAPPING
        assert await get_mapping(tenant_id) == expected, tenant_id


async def test_get_provider_does_not_modify_the_static_provider_config():
    await init_with_tenant_mapping()

    for tenant_id in ["public", "t1", "public"]:
        await get_provider(tenant_id, THIRD_PARTY_ID)

    static_config = ThirdPartyRecipe.get_instance().providers[0].config
    assert static_config.user_info_map is None
    assert static_config.generate_fake_email is None
    assert static_config.clients is not None
    assert [c.client_id for c in static_config.clients] == ["public-client"]


async def test_get_provider_does_not_modify_a_static_built_in_provider_config():
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(),
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=[
                            ProviderInput(
                                config=ProviderConfig(
                                    third_party_id="github",
                                    clients=[
                                        ProviderClientConfig(
                                            client_id="github-client",
                                            client_secret="github-secret",
                                        )
                                    ],
                                )
                            )
                        ]
                    )
                ),
            ],
        )
    )

    provider = await get_provider("public", "github")
    assert provider is not None
    assert provider.config.name == "Github"
    assert provider.config.validate_access_token is not None

    static_config = ThirdPartyRecipe.get_instance().providers[0].config
    assert static_config.name is None
    assert static_config.authorization_endpoint is None
    assert static_config.token_endpoint is None
    assert static_config.validate_access_token is None
    assert static_config.user_info_map is None


async def test_merge_config_does_not_modify_its_inputs():
    static_user_info_map = UserInfoMap(
        from_id_token_payload=UserFields(user_id="sub", email="email"),
        from_user_info_api=UserFields(user_id="id", email="email"),
    )
    static_client = ProviderClientConfig(
        client_id="static-client", additional_config={"hd": "corp.example"}
    )
    static_config = ProviderConfig(
        third_party_id=THIRD_PARTY_ID,
        clients=[static_client],
        user_info_map=static_user_info_map,
    )
    core_config = ProviderConfig(
        third_party_id=THIRD_PARTY_ID,
        user_info_map=UserInfoMap(
            from_id_token_payload=UserFields(email="name"),
            from_user_info_api=None,
        ),
    )

    merged = merge_config(static_config, core_config)

    assert merged.user_info_map is not None
    assert merged.user_info_map.from_id_token_payload is not None
    assert merged.user_info_map.from_id_token_payload.email == "name"
    assert merged.user_info_map.from_id_token_payload.user_id == "sub"
    assert merged.clients is not None
    merged.clients[0].additional_config = {"hd": "*"}
    merged.user_info_map.from_id_token_payload.user_id = "other"

    assert static_config.user_info_map is static_user_info_map
    assert static_user_info_map.from_id_token_payload is not None
    assert static_user_info_map.from_id_token_payload.email == "email"
    assert static_user_info_map.from_id_token_payload.user_id == "sub"
    assert static_config.clients == [static_client]
    assert static_client.additional_config == {"hd": "corp.example"}
    assert core_config.user_info_map is not None
    assert core_config.user_info_map.from_user_info_api is None
