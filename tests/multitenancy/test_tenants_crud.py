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
from fastapi import FastAPI
from pytest import mark, fixture
from starlette.testclient import TestClient
from typing import Any, Dict

from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import emailpassword, multitenancy, session
from tests.utils import (
    setup_function,
    teardown_function,
    get_st_init_args,
    start_st,
    setup_multitenancy_feature,
)

_ = setup_function
_ = teardown_function

pytestmark = mark.asyncio

from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
    list_all_tenants,
    get_tenant,
    delete_tenant,
    create_or_update_third_party_config,
    delete_third_party_config,
    associate_user_to_tenant,
    dissociate_user_from_tenant,
)
from supertokens_python.recipe.emailpassword.asyncio import sign_up, get_user_by_id
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.recipe.multitenancy.interfaces import TenantConfig
from supertokens_python.recipe.thirdparty.provider import (
    ProviderConfig,
    ProviderClientConfig,
    UserInfoMap,
    UserFields,
)


@fixture(scope="function")
async def client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


async def test_tenant_crud():
    args = get_st_init_args([multitenancy.init()])
    init(**args)
    start_st()
    setup_multitenancy_feature()

    await create_or_update_tenant("t1", TenantConfig(email_password_enabled=True))
    await create_or_update_tenant("t2", TenantConfig(passwordless_enabled=True))
    await create_or_update_tenant("t3", TenantConfig(third_party_enabled=True))

    tenants = await list_all_tenants()
    assert len(tenants.tenants) == 4

    t1_config = await get_tenant("t1")
    assert t1_config is not None
    assert t1_config.emailpassword.enabled is True
    assert t1_config.passwordless.enabled is False
    assert t1_config.third_party.enabled is False
    assert t1_config.core_config == {}

    t2_config = await get_tenant("t2")
    assert t2_config is not None
    assert t2_config.emailpassword.enabled is False
    assert t2_config.passwordless.enabled is True
    assert t2_config.third_party.enabled is False
    assert t2_config.core_config == {}

    t3_config = await get_tenant("t3")
    assert t3_config is not None
    assert t3_config.emailpassword.enabled is False
    assert t3_config.passwordless.enabled is False
    assert t3_config.third_party.enabled is True
    assert t3_config.core_config == {}

    # update tenant1 to add passwordless:
    await create_or_update_tenant("t1", TenantConfig(passwordless_enabled=True))
    t1_config = await get_tenant("t1")
    assert t1_config is not None
    assert t1_config.emailpassword.enabled is True
    assert t1_config.passwordless.enabled is True
    assert t1_config.third_party.enabled is False
    assert t1_config.core_config == {}

    # update tenant1 to add thirdparty:
    await create_or_update_tenant("t1", TenantConfig(third_party_enabled=True))
    t1_config = await get_tenant("t1")
    assert t1_config is not None
    assert t1_config is not None
    assert t1_config.emailpassword.enabled is True
    assert t1_config.passwordless.enabled is True
    assert t1_config.third_party.enabled is True
    assert t1_config.core_config == {}

    # delete tenant2:
    await delete_tenant("t2")
    tenants = await list_all_tenants()
    assert len(tenants.tenants) == 3


async def test_tenant_thirdparty_config():
    args = get_st_init_args([multitenancy.init()])
    init(**args)
    start_st()
    setup_multitenancy_feature()

    await create_or_update_tenant("t1", TenantConfig(email_password_enabled=True))
    await create_or_update_third_party_config(
        "t1",
        config=ProviderConfig(
            third_party_id="google",
            name="Google",
            clients=[ProviderClientConfig(client_id="abcd")],
        ),
    )

    tenant_config = await get_tenant("t1")
    assert tenant_config is not None

    assert len(tenant_config.third_party.providers) == 1
    provider = tenant_config.third_party.providers[0]
    assert provider.third_party_id == "google"
    assert provider.clients is not None
    assert len(provider.clients) == 1
    assert provider.clients[0].client_id == "abcd"
    assert provider.clients[0].client_secret is None
    assert provider.clients[0].force_pkce is False
    assert provider.require_email is True

    async def validate_id_token_payload(
        _: Dict[str, Any], __: Any, ___: Dict[str, Any]
    ):
        return

    async def generate_fake_email(_: str, __: str, ___: Dict[str, Any]):
        return "fake@example.com"

    # update thirdparty config
    await create_or_update_third_party_config(
        "t1",
        ProviderConfig(
            third_party_id="google",
            name="Custom name",
            clients=[
                ProviderClientConfig(
                    client_id="efgh",
                    client_secret="ijkl",
                    scope=["m", "n"],
                    force_pkce=True,
                    additional_config={"o": "p"},
                )
            ],
            authorization_endpoint="http://localhost:8080/auth",
            authorization_endpoint_query_params={"a": "b"},
            token_endpoint="http://localhost:8080/token",
            token_endpoint_body_params={"c": "d"},
            user_info_endpoint="http://localhost:8080/userinfo",
            user_info_endpoint_query_params={"e": "f"},
            user_info_endpoint_headers={"g": "h"},
            jwks_uri="http://localhost:8080/.well-known/jwks.json",
            oidc_discovery_endpoint="http://localhost:8080/.well-known/openid-configuration",
            user_info_map=UserInfoMap(
                from_id_token_payload=UserFields(
                    user_id="userid",
                    email="email",
                    email_verified="is_verified",
                ),
                from_user_info_api=UserFields(),
            ),
            require_email=False,
            validate_id_token_payload=validate_id_token_payload,
            generate_fake_email=generate_fake_email,
        ),
    )

    tenant_config = await get_tenant("t1")
    assert tenant_config is not None
    assert len(tenant_config.third_party.providers) == 1
    provider = tenant_config.third_party.providers[0]
    assert provider.third_party_id == "google"
    assert provider.name == "Custom name"
    assert provider.clients is not None
    assert len(provider.clients) == 1
    assert provider.clients[0].client_id == "efgh"
    assert provider.clients[0].client_secret == "ijkl"
    assert provider.clients[0].scope == ["m", "n"]
    assert provider.clients[0].force_pkce is True
    assert provider.clients[0].additional_config == {"o": "p"}

    assert provider.name == "Custom name"
    assert provider.authorization_endpoint == "http://localhost:8080/auth"
    assert provider.authorization_endpoint_query_params == {"a": "b"}
    assert provider.token_endpoint == "http://localhost:8080/token"
    assert provider.token_endpoint_body_params == {"c": "d"}
    assert provider.user_info_endpoint == "http://localhost:8080/userinfo"
    assert provider.user_info_endpoint_query_params == {"e": "f"}
    assert provider.user_info_endpoint_headers == {"g": "h"}
    assert provider.jwks_uri == "http://localhost:8080/.well-known/jwks.json"
    assert (
        provider.oidc_discovery_endpoint
        == "http://localhost:8080/.well-known/openid-configuration"
    )

    assert provider.user_info_map is not None
    assert provider.user_info_map.from_user_info_api is not None
    assert provider.user_info_map.from_id_token_payload is not None

    assert provider.user_info_map.from_id_token_payload.user_id == "userid"
    assert provider.user_info_map.from_id_token_payload.email == "email"
    assert provider.user_info_map.from_id_token_payload.email_verified == "is_verified"
    assert provider.user_info_map.from_user_info_api is not None
    assert provider.user_info_map.from_user_info_api.user_id is None
    assert provider.user_info_map.from_user_info_api.email is None
    assert provider.user_info_map.from_user_info_api.email_verified is None

    assert provider.require_email is False
    assert provider.validate_id_token_payload is None
    assert provider.generate_fake_email is None

    # delete thirdparty config
    await delete_third_party_config("t1", "google")

    tenant_config = await get_tenant("t1")
    assert tenant_config is not None
    assert len(tenant_config.third_party.providers) == 0


async def test_user_association_and_disassociation_with_tenants():
    args = get_st_init_args([session.init(), emailpassword.init(), multitenancy.init()])
    init(**args)
    start_st()
    setup_multitenancy_feature()

    await create_or_update_tenant("t1", TenantConfig(email_password_enabled=True))
    await create_or_update_tenant("t2", TenantConfig(passwordless_enabled=True))
    await create_or_update_tenant("t3", TenantConfig(third_party_enabled=True))

    signup_response = await sign_up("public", "test@example.com", "password1")
    assert isinstance(signup_response, SignUpOkResult)
    user_id = signup_response.user.user_id

    await associate_user_to_tenant("t1", user_id)
    await associate_user_to_tenant("t2", user_id)
    await associate_user_to_tenant("t3", user_id)

    user = await get_user_by_id(user_id)
    assert user is not None
    assert len(user.tenant_ids) == 4  # public + 3 tenants

    await dissociate_user_from_tenant("t1", user_id)
    await dissociate_user_from_tenant("t2", user_id)
    await dissociate_user_from_tenant("t3", user_id)

    user = await get_user_by_id(user_id)
    assert user is not None
    assert len(user.tenant_ids) == 1  # public only
