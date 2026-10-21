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
from typing import Any, Dict, Optional
from urllib.parse import parse_qs

import httpx
import respx
from fastapi import FastAPI
from pytest import mark, raises
from starlette.testclient import TestClient
from supertokens_python import init
from supertokens_python.asyncio import list_users_by_account_info
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session, thirdparty
from supertokens_python.recipe.thirdparty.provider import (
    Provider,
    ProviderClientConfig,
    ProviderConfig,
    ProviderInput,
    RedirectUriInfo,
)
from supertokens_python.recipe.thirdparty.providers.config_utils import (
    find_and_create_provider_instance,
)
from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo
from supertokens_python.types.base import AccountInfoInput

from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

GOOGLE_CLIENTS = [
    ProviderClientConfig(
        client_type="web", client_id="web-client", client_secret="web-secret"
    ),
    ProviderClientConfig(client_type="android", client_id="android-client"),
]


async def get_provider(
    config: ProviderConfig, client_type: Optional[str] = None
) -> Provider:
    # Providers are created the same way the sign in up API creates them: a new instance for every request
    provider = await find_and_create_provider_instance(
        [ProviderInput(config=config)], config.third_party_id, client_type, {}
    )
    assert provider is not None
    return provider


def mock_google_discovery(mocker: respx.MockRouter):
    mocker.get("https://accounts.google.com/.well-known/openid-configuration").mock(
        return_value=httpx.Response(
            200,
            json={
                "issuer": "https://accounts.google.com",
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            },
        )
    )


def mock_google_token_info(
    mocker: respx.MockRouter, status: int, body: Any
) -> respx.Route:
    return mocker.post("https://oauth2.googleapis.com/tokeninfo").mock(
        return_value=httpx.Response(status, json=body)
    )


def mock_google_user_info(mocker: respx.MockRouter) -> respx.Route:
    return mocker.get("https://openidconnect.googleapis.com/v1/userinfo").mock(
        return_value=httpx.Response(
            200,
            json={
                "sub": "google-user-1",
                "email": "user@example.com",
                "email_verified": True,
            },
        )
    )


def google_config(**kwargs: Any) -> ProviderConfig:
    return ProviderConfig(third_party_id="google", clients=GOOGLE_CLIENTS, **kwargs)


async def test_google_accepts_an_access_token_of_a_configured_client():
    with respx.mock(assert_all_called=False) as mocker:
        mock_google_discovery(mocker)
        token_info = mock_google_token_info(
            mocker, 200, {"aud": "web-client", "azp": "web-client"}
        )
        user_info = mock_google_user_info(mocker)
        provider = await get_provider(google_config(), "web")

        res = await provider.get_user_info({"access_token": "token-1"}, {})

        assert token_info.called
        assert user_info.called
        assert res.third_party_user_id == "google-user-1"
        # The token is sent in the body, not in the URL
        request = token_info.calls.last.request
        assert parse_qs(request.content.decode()) == {"access_token": ["token-1"]}
        assert "token-1" not in str(request.url)


async def test_google_accepts_an_access_token_requested_by_another_configured_client():
    with respx.mock(assert_all_called=False) as mocker:
        mock_google_discovery(mocker)
        mock_google_token_info(
            mocker, 200, {"aud": "some-other-client", "azp": "android-client"}
        )
        user_info = mock_google_user_info(mocker)
        provider = await get_provider(google_config(), "web")

        await provider.get_user_info({"access_token": "token-1"}, {})

        assert user_info.called


async def test_google_rejects_an_access_token_of_a_client_that_is_not_configured():
    with respx.mock(assert_all_called=False) as mocker:
        mock_google_discovery(mocker)
        mock_google_token_info(
            mocker, 200, {"aud": "some-other-client", "azp": "some-other-client"}
        )
        user_info = mock_google_user_info(mocker)
        provider = await get_provider(google_config(), "web")

        with raises(Exception, match="does not belong to your application"):
            await provider.get_user_info({"access_token": "token-1"}, {})
        assert not user_info.called


async def test_google_rejects_an_access_token_the_token_info_api_rejects():
    with respx.mock(assert_all_called=False) as mocker:
        mock_google_discovery(mocker)
        mock_google_token_info(
            mocker,
            400,
            {"error": "invalid_token", "error_description": "Invalid Value"},
        )
        user_info = mock_google_user_info(mocker)
        provider = await get_provider(google_config(), "web")

        with raises(Exception, match="Invalid access token"):
            await provider.get_user_info({"access_token": "token-1"}, {})
        assert not user_info.called


async def test_google_reports_other_token_info_api_errors_with_their_status():
    with respx.mock(assert_all_called=False) as mocker:
        mock_google_discovery(mocker)
        mock_google_token_info(mocker, 503, {"error": "unavailable"})
        provider = await get_provider(google_config(), "web")

        with raises(
            Exception,
            match=r"Could not check the access token with Google \(status 503\)",
        ):
            await provider.get_user_info({"access_token": "token-1"}, {})


async def test_google_does_not_check_the_access_token_from_the_code_exchange():
    with respx.mock(assert_all_called=False) as mocker:
        mock_google_discovery(mocker)
        mocker.post("https://oauth2.googleapis.com/token").mock(
            return_value=httpx.Response(200, json={"access_token": "exchanged-token"})
        )
        token_info = mock_google_token_info(
            mocker, 200, {"aud": "some-other-client", "azp": "some-other-client"}
        )
        user_info = mock_google_user_info(mocker)
        provider = await get_provider(google_config(), "web")

        oauth_tokens = await provider.exchange_auth_code_for_oauth_tokens(
            RedirectUriInfo(
                redirect_uri_on_provider_dashboard="https://example.com/auth/callback/google",
                redirect_uri_query_params={"code": "code"},
                pkce_code_verifier=None,
            ),
            {},
        )
        await provider.get_user_info(oauth_tokens, {})

        assert user_info.called
        assert not token_info.called


async def test_google_checks_an_access_token_that_is_not_the_one_from_the_code_exchange():
    with respx.mock(assert_all_called=False) as mocker:
        mock_google_discovery(mocker)
        mocker.post("https://oauth2.googleapis.com/token").mock(
            return_value=httpx.Response(200, json={"access_token": "exchanged-token"})
        )
        mock_google_token_info(
            mocker, 200, {"aud": "some-other-client", "azp": "some-other-client"}
        )
        provider = await get_provider(google_config(), "web")

        await provider.exchange_auth_code_for_oauth_tokens(
            RedirectUriInfo(
                redirect_uri_on_provider_dashboard="https://example.com/auth/callback/google",
                redirect_uri_query_params={"code": "code"},
                pkce_code_verifier=None,
            ),
            {},
        )
        with raises(Exception, match="does not belong to your application"):
            await provider.get_user_info({"access_token": "another-token"}, {})


async def test_google_does_not_check_if_the_config_sets_validate_access_token():
    called_with: Dict[str, Any] = {}

    async def validate_access_token(access_token: str, *_: Any):
        called_with["access_token"] = access_token

    with respx.mock(assert_all_called=False) as mocker:
        mock_google_discovery(mocker)
        token_info = mock_google_token_info(
            mocker, 200, {"aud": "some-other-client", "azp": "some-other-client"}
        )
        user_info = mock_google_user_info(mocker)
        provider = await get_provider(
            google_config(validate_access_token=validate_access_token), "web"
        )

        await provider.get_user_info({"access_token": "token-1"}, {})

        assert called_with == {"access_token": "token-1"}
        assert user_info.called
        assert not token_info.called


async def test_google_workspaces_checks_the_access_token():
    with respx.mock(assert_all_called=False) as mocker:
        mock_google_discovery(mocker)
        mock_google_token_info(
            mocker, 200, {"aud": "some-other-client", "azp": "some-other-client"}
        )
        provider = await get_provider(
            ProviderConfig(
                third_party_id="google-workspaces", clients=[GOOGLE_CLIENTS[0]]
            )
        )

        with raises(Exception, match="does not belong to your application"):
            await provider.get_user_info({"access_token": "token-1"}, {})


FACEBOOK_CONFIG = ProviderConfig(
    third_party_id="facebook",
    clients=[ProviderClientConfig(client_id="fb-app", client_secret="fb-secret")],
)


def mock_debug_token(mocker: respx.MockRouter, status: int, body: Any) -> respx.Route:
    return mocker.get("https://graph.facebook.com/debug_token").mock(
        return_value=httpx.Response(status, json=body)
    )


def mock_facebook_user_info(mocker: respx.MockRouter) -> respx.Route:
    return mocker.get("https://graph.facebook.com/me").mock(
        return_value=httpx.Response(
            200, json={"id": "fb-user-1", "email": "user@example.com"}
        )
    )


async def test_facebook_accepts_a_valid_access_token_of_the_configured_app():
    with respx.mock(assert_all_called=False) as mocker:
        debug_token = mock_debug_token(
            mocker,
            200,
            {"data": {"app_id": "fb-app", "is_valid": True, "user_id": "fb-user-1"}},
        )
        user_info = mock_facebook_user_info(mocker)
        provider = await get_provider(FACEBOOK_CONFIG)

        res = await provider.get_user_info({"access_token": "fb-token"}, {})

        assert user_info.called
        assert res.third_party_user_id == "fb-user-1"
        params = debug_token.calls.last.request.url.params
        assert params["input_token"] == "fb-token"
        assert params["access_token"] == "fb-app|fb-secret"


async def test_facebook_rejects_an_access_token_of_another_app():
    with respx.mock(assert_all_called=False) as mocker:
        mock_debug_token(
            mocker, 200, {"data": {"app_id": "another-app", "is_valid": True}}
        )
        user_info = mock_facebook_user_info(mocker)
        provider = await get_provider(FACEBOOK_CONFIG)

        with raises(Exception, match="does not belong to your application"):
            await provider.get_user_info({"access_token": "fb-token"}, {})
        assert not user_info.called


async def test_facebook_rejects_an_invalid_access_token():
    with respx.mock(assert_all_called=False) as mocker:
        mock_debug_token(mocker, 200, {"data": {"app_id": "fb-app", "is_valid": False}})
        provider = await get_provider(FACEBOOK_CONFIG)

        with raises(Exception, match="Invalid access token"):
            await provider.get_user_info({"access_token": "fb-token"}, {})


async def test_facebook_rejects_an_access_token_of_another_app_that_facebook_wont_debug():
    with respx.mock(assert_all_called=False) as mocker:
        mock_debug_token(
            mocker,
            400,
            {
                "error": {
                    "message": "(#100) The App_id in the input_token did not match the Viewing App",
                    "type": "OAuthException",
                    "code": 100,
                }
            },
        )
        user_info = mock_facebook_user_info(mocker)
        provider = await get_provider(FACEBOOK_CONFIG)

        with raises(Exception, match="does not belong to your application"):
            await provider.get_user_info({"access_token": "fb-token"}, {})
        assert not user_info.called


async def test_facebook_reports_a_failed_debug_token_call():
    with respx.mock(assert_all_called=False) as mocker:
        mock_debug_token(
            mocker,
            400,
            {"error": {"message": "Invalid OAuth access token", "code": 190}},
        )
        provider = await get_provider(FACEBOOK_CONFIG)

        with raises(
            Exception,
            match=r"Could not check the access token with Facebook \(status 400\)",
        ):
            await provider.get_user_info({"access_token": "fb-token"}, {})


async def test_facebook_reports_a_missing_client_secret_without_calling_facebook():
    with respx.mock(assert_all_called=False) as mocker:
        debug_token = mock_debug_token(
            mocker, 200, {"data": {"app_id": "fb-app", "is_valid": True}}
        )
        provider = await get_provider(
            ProviderConfig(
                third_party_id="facebook",
                clients=[ProviderClientConfig(client_id="fb-app")],
            )
        )

        with raises(Exception, match="client_secret"):
            await provider.get_user_info({"access_token": "fb-token"}, {})
        assert not debug_token.called


GITLAB_CONFIG = ProviderConfig(
    third_party_id="gitlab",
    clients=[
        ProviderClientConfig(
            client_id="gitlab-app",
            client_secret="gitlab-secret",
            additional_config={"gitlabBaseUrl": "https://gitlab.example.com"},
        )
    ],
)


def mock_gitlab(mocker: respx.MockRouter, status: int, body: Any):
    mocker.get("https://gitlab.example.com/.well-known/openid-configuration").mock(
        return_value=httpx.Response(
            200,
            json={
                "issuer": "https://gitlab.example.com",
                "authorization_endpoint": "https://gitlab.example.com/oauth/authorize",
                "token_endpoint": "https://gitlab.example.com/oauth/token",
                "userinfo_endpoint": "https://gitlab.example.com/oauth/userinfo",
                "jwks_uri": "https://gitlab.example.com/oauth/discovery/keys",
            },
        )
    )
    token_info = mocker.get("https://gitlab.example.com/oauth/token/info").mock(
        return_value=httpx.Response(status, json=body)
    )
    user_info = mocker.get("https://gitlab.example.com/oauth/userinfo").mock(
        return_value=httpx.Response(
            200,
            json={
                "sub": "gl-user-1",
                "email": "user@example.com",
                "email_verified": True,
            },
        )
    )
    return token_info, user_info


async def test_gitlab_accepts_an_access_token_of_the_configured_application():
    with respx.mock(assert_all_called=False) as mocker:
        token_info, user_info = mock_gitlab(
            mocker, 200, {"application": {"uid": "gitlab-app"}}
        )
        provider = await get_provider(GITLAB_CONFIG)

        await provider.get_user_info({"access_token": "gl-token"}, {})

        assert token_info.called
        assert (
            token_info.calls.last.request.headers["authorization"] == "Bearer gl-token"
        )
        assert user_info.called


async def test_gitlab_rejects_an_access_token_of_another_application():
    with respx.mock(assert_all_called=False) as mocker:
        _, user_info = mock_gitlab(mocker, 200, {"application": {"uid": "another-app"}})
        provider = await get_provider(GITLAB_CONFIG)

        with raises(Exception, match="does not belong to your application"):
            await provider.get_user_info({"access_token": "gl-token"}, {})
        assert not user_info.called


async def test_gitlab_rejects_an_access_token_gitlab_does_not_accept():
    with respx.mock(assert_all_called=False) as mocker:
        mock_gitlab(mocker, 401, {"error": "invalid_token"})
        provider = await get_provider(GITLAB_CONFIG)

        with raises(Exception, match="Invalid access token"):
            await provider.get_user_info({"access_token": "gl-token"}, {})


DISCORD_CONFIG = ProviderConfig(
    third_party_id="discord",
    clients=[
        ProviderClientConfig(client_id="discord-app", client_secret="discord-secret")
    ],
)


def mock_discord(mocker: respx.MockRouter, status: int, body: Any):
    auth_info = mocker.get("https://discord.com/api/oauth2/@me").mock(
        return_value=httpx.Response(status, json=body)
    )
    user_info = mocker.get("https://discord.com/api/users/@me").mock(
        return_value=httpx.Response(
            200, json={"id": "dc-user-1", "email": "user@example.com", "verified": True}
        )
    )
    return auth_info, user_info


async def test_discord_accepts_an_access_token_of_the_configured_application():
    with respx.mock(assert_all_called=False) as mocker:
        auth_info, user_info = mock_discord(
            mocker, 200, {"application": {"id": "discord-app"}}
        )
        provider = await get_provider(DISCORD_CONFIG)

        await provider.get_user_info({"access_token": "dc-token"}, {})

        assert (
            auth_info.calls.last.request.headers["authorization"] == "Bearer dc-token"
        )
        assert user_info.called


async def test_discord_rejects_an_access_token_of_another_application():
    with respx.mock(assert_all_called=False) as mocker:
        _, user_info = mock_discord(mocker, 200, {"application": {"id": "another-app"}})
        provider = await get_provider(DISCORD_CONFIG)

        with raises(Exception, match="does not belong to your application"):
            await provider.get_user_info({"access_token": "dc-token"}, {})
        assert not user_info.called


async def test_discord_rejects_an_access_token_discord_does_not_accept():
    with respx.mock(assert_all_called=False) as mocker:
        mock_discord(mocker, 401, {"message": "401: Unauthorized", "code": 0})
        provider = await get_provider(DISCORD_CONFIG)

        with raises(Exception, match="Invalid access token"):
            await provider.get_user_info({"access_token": "dc-token"}, {})


# Sign in up API (needs a core)


def init_with_google():
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(get_token_transfer_method=lambda _, __, ___: "header"),
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=[ProviderInput(config=google_config())]
                    )
                ),
            ],
        )
    )


def get_client() -> TestClient:
    app = FastAPI()
    app.add_middleware(get_middleware())
    return TestClient(app, raise_server_exceptions=False)


async def get_google_users():
    return await list_users_by_account_info(
        "public",
        AccountInfoInput(
            third_party=ThirdPartyInfo(
                third_party_id="google", third_party_user_id="google-user-1"
            )
        ),
    )


async def test_sign_in_up_api_rejects_an_access_token_of_a_client_that_is_not_configured():
    init_with_google()
    client = get_client()
    with respx.mock(assert_all_called=False, assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mock_google_discovery(mocker)
        mock_google_token_info(
            mocker, 200, {"aud": "some-other-client", "azp": "some-other-client"}
        )
        mock_google_user_info(mocker)

        res = client.post(
            "/auth/signinup",
            json={
                "thirdPartyId": "google",
                "clientType": "web",
                "oAuthTokens": {"access_token": "token-1"},
            },
        )

    assert res.status_code != 200 or res.json().get("status") != "OK"
    assert len(await get_google_users()) == 0


async def test_sign_in_up_api_signs_in_with_an_access_token_of_a_configured_client():
    init_with_google()
    client = get_client()
    with respx.mock(assert_all_called=False, assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mock_google_discovery(mocker)
        token_info = mock_google_token_info(
            mocker, 200, {"aud": "android-client", "azp": "android-client"}
        )
        mock_google_user_info(mocker)

        res = client.post(
            "/auth/signinup",
            json={
                "thirdPartyId": "google",
                "clientType": "android",
                "oAuthTokens": {"access_token": "token-1"},
            },
        )

    assert token_info.called
    assert res.json()["status"] == "OK"
    assert len(await get_google_users()) == 1


async def test_sign_in_up_api_does_not_call_token_info_when_signing_in_with_a_code():
    init_with_google()
    client = get_client()
    with respx.mock(assert_all_called=False, assert_all_mocked=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mock_google_discovery(mocker)
        mocker.post("https://oauth2.googleapis.com/token").mock(
            return_value=httpx.Response(200, json={"access_token": "exchanged-token"})
        )
        token_info = mock_google_token_info(
            mocker, 200, {"aud": "some-other-client", "azp": "some-other-client"}
        )
        mock_google_user_info(mocker)

        res = client.post(
            "/auth/signinup",
            json={
                "thirdPartyId": "google",
                "clientType": "web",
                "redirectURIInfo": {
                    "redirectURIOnProviderDashboard": "https://supertokens.io/auth/callback/google",
                    "redirectURIQueryParams": {"code": "code"},
                },
            },
        )

    assert res.json()["status"] == "OK"
    assert not token_info.called
