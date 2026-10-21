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
from typing import Any, Dict

import httpx
import respx
from fastapi import FastAPI
from pytest import fixture, mark
from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import dashboard, multitenancy, session, thirdparty
from supertokens_python.recipe.thirdparty.asyncio import get_provider
from supertokens_python.recipe.thirdparty.provider import (
    ProviderClientConfig,
    ProviderConfig,
    ProviderInput,
)
from supertokens_python.recipe.thirdparty.providers.config_utils import OIDC_INFO_MAP
from supertokens_python.recipe.thirdparty.recipe import ThirdPartyRecipe

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

API_KEY = "someKey"


@fixture(autouse=True)
def clear_oidc_discovery_cache():
    # The discovery responses mocked here must not be reused by other tests
    OIDC_INFO_MAP.clear()
    yield
    OIDC_INFO_MAP.clear()


@fixture(scope="function")
def app():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


def discovery_document(issuer: str) -> Dict[str, Any]:
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/jwks",
    }


def mock_discovery(mocker: respx.MockRouter, issuer: str):
    mocker.get(f"{issuer}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document(issuer))
    )


def init_with_static_provider(provider: ProviderInput):
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(),
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=[provider]
                    )
                ),
                multitenancy.init(),
                dashboard.init(api_key=API_KEY),
            ],
        )
    )


def get_third_party_config(app: TestClient, query: str):
    return app.get(
        f"/auth/public/dashboard/api/thirdparty/config?{query}",
        headers={"Authorization": f"Bearer {API_KEY}"},
    )


async def test_get_third_party_config_with_okta_domain_does_not_change_static_provider(
    app: TestClient,
):
    okta_domain = "https://okta.corp.example"
    other_domain = "https://other.example"
    init_with_static_provider(
        ProviderInput(
            config=ProviderConfig(
                third_party_id="okta",
                clients=[
                    ProviderClientConfig(
                        client_id="okta-client",
                        client_secret="okta-secret",
                        additional_config={"oktaDomain": okta_domain},
                    )
                ],
            )
        )
    )

    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mock_discovery(mocker, okta_domain)
        mock_discovery(mocker, other_domain)

        res = get_third_party_config(
            app, f"thirdPartyId=okta&oktaDomain={other_domain}"
        )
        assert res.status_code == 200
        body = res.json()
        assert body["status"] == "OK"
        assert (
            body["providerConfig"]["clients"][0]["additionalConfig"]["oktaDomain"]
            == other_domain
        )

        static_config = ThirdPartyRecipe.get_instance().providers[0].config
        assert static_config.clients is not None
        assert static_config.clients[0].additional_config == {"oktaDomain": okta_domain}

        provider = await get_provider("public", "okta")
        assert provider is not None
        assert provider.config.additional_config == {"oktaDomain": okta_domain}
        assert provider.config.authorization_endpoint == f"{okta_domain}/authorize"
        assert provider.config.token_endpoint == f"{okta_domain}/token"
        assert provider.config.jwks_uri == f"{okta_domain}/jwks"


async def test_get_third_party_config_with_hd_does_not_change_static_provider(
    app: TestClient,
):
    init_with_static_provider(
        ProviderInput(
            config=ProviderConfig(
                third_party_id="google-workspaces",
                clients=[
                    ProviderClientConfig(
                        client_id="gw-client",
                        client_secret="gw-secret",
                        additional_config={"hd": "corp.example"},
                    )
                ],
            )
        )
    )

    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mock_discovery(mocker, "https://accounts.google.com")

        res = get_third_party_config(app, "thirdPartyId=google-workspaces&hd=*")
        assert res.status_code == 200
        body = res.json()
        assert body["status"] == "OK"
        assert body["providerConfig"]["clients"][0]["additionalConfig"]["hd"] == "*"

        static_config = ThirdPartyRecipe.get_instance().providers[0].config
        assert static_config.clients is not None
        assert static_config.clients[0].additional_config == {"hd": "corp.example"}

        provider = await get_provider("public", "google-workspaces")
        assert provider is not None
        assert provider.config.additional_config == {"hd": "corp.example"}
