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
import json
from typing import Any, Dict, List, cast

import httpx
import respx
from fastapi import FastAPI
from pytest import fixture, mark, raises
from starlette.testclient import TestClient
from supertokens_python import init
from supertokens_python.asyncio import list_users_by_account_info
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session, thirdparty
from supertokens_python.recipe.thirdparty.asyncio import get_provider
from supertokens_python.recipe.thirdparty.provider import (
    ProviderClientConfig,
    ProviderConfig,
    ProviderConfigForClient,
    ProviderInput,
)
from supertokens_python.recipe.thirdparty.providers.github import (
    validate_access_token as default_github_validate_access_token,
)
from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo
from supertokens_python.types.base import AccountInfoInput

from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

CLIENT_ID = "github-client"
CLIENT_SECRET = "github-secret"
ACCESS_TOKEN = "gho_token"
GITHUB_USER_ID = "4242"


@fixture(scope="function")
def fastapi_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app, raise_server_exceptions=False)


def init_with_github(provider_config: Dict[str, Any]):
    provider_config = {
        "clients": [
            ProviderClientConfig(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
        ],
        **provider_config,
    }
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(get_token_transfer_method=lambda _, __, ___: "header"),
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=[
                            ProviderInput(
                                config=ProviderConfig(
                                    third_party_id="github",
                                    **provider_config,
                                )
                            )
                        ]
                    )
                ),
            ],
        )
    )


def mock_github_user_info(mocker: respx.MockRouter) -> List[respx.Route]:
    return [
        mocker.get("https://api.github.com/user").mock(
            return_value=httpx.Response(200, json={"id": int(GITHUB_USER_ID)})
        ),
        mocker.get("https://api.github.com/user/emails").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"email": "gh-user@example.com", "primary": True, "verified": True}
                ],
            )
        ),
    ]


def header_values(request: httpx.Request, name: str) -> List[str]:
    return [value for key, value in request.headers.multi_items() if key == name]


def mock_github_token_check(
    mocker: respx.MockRouter, status: int, body: Dict[str, Any]
) -> respx.Route:
    def respond(request: httpx.Request) -> httpx.Response:
        # Like GitHub, only accept a JSON body sent with a single JSON content type
        try:
            request_body = json.loads(request.content)
        except ValueError:
            request_body = None
        if header_values(request, "content-type") != ["application/json"] or (
            not isinstance(request_body, dict) or "access_token" not in request_body
        ):
            return httpx.Response(400, json={"message": "Problems parsing JSON"})
        return httpx.Response(status, json=body)

    return mocker.post(f"https://api.github.com/applications/{CLIENT_ID}/token").mock(
        side_effect=respond
    )


def sign_in_up(fastapi_client: TestClient):
    return fastapi_client.post(
        "/auth/signinup",
        json={"thirdPartyId": "github", "oAuthTokens": {"access_token": ACCESS_TOKEN}},
    )


async def count_github_users() -> int:
    users = await list_users_by_account_info(
        "public",
        AccountInfoInput(third_party=ThirdPartyInfo(GITHUB_USER_ID, "github")),
    )
    return len(users)


async def test_github_sign_in_fails_if_token_check_rejects_the_access_token(
    fastapi_client: TestClient,
):
    init_with_github({})

    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        token_check = mock_github_token_check(mocker, 404, {"message": "Not Found"})
        mock_github_user_info(mocker)

        res = sign_in_up(fastapi_client)

    assert token_check.called
    assert ACCESS_TOKEN.encode() in token_check.calls.last.request.content
    assert res.status_code != 200 or res.json().get("status") != "OK"
    assert await count_github_users() == 0


async def test_github_sign_in_fails_if_access_token_belongs_to_another_application(
    fastapi_client: TestClient,
):
    init_with_github({})

    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        token_check = mock_github_token_check(
            mocker, 200, {"app": {"client_id": "some-other-client"}}
        )
        mock_github_user_info(mocker)

        res = sign_in_up(fastapi_client)

    assert token_check.called
    assert res.status_code != 200 or res.json().get("status") != "OK"
    assert await count_github_users() == 0


async def test_github_sign_in_works_if_token_check_accepts_the_access_token(
    fastapi_client: TestClient,
):
    init_with_github({})

    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        token_check = mock_github_token_check(
            mocker, 200, {"app": {"client_id": CLIENT_ID}}
        )
        user_info_routes = mock_github_user_info(mocker)

        res = sign_in_up(fastapi_client)

    assert token_check.called
    assert all(route.called for route in user_info_routes)
    assert res.status_code == 200
    assert res.json()["status"] == "OK"
    assert await count_github_users() == 1


async def test_github_sign_in_uses_custom_validate_access_token_that_rejects(
    fastapi_client: TestClient,
):
    calls: List[Dict[str, Any]] = []

    async def validate_access_token(
        access_token: str,
        client_config: ProviderConfigForClient,
        user_context: Dict[str, Any],
    ):
        calls.append(
            {
                "access_token": access_token,
                "client_id": client_config.client_id,
                "user_context": user_context,
            }
        )
        raise Exception("token rejected")

    init_with_github({"validate_access_token": validate_access_token})

    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mock_github_user_info(mocker)

        res = sign_in_up(fastapi_client)

    assert len(calls) == 1
    assert calls[0]["access_token"] == ACCESS_TOKEN
    assert calls[0]["client_id"] == CLIENT_ID
    assert calls[0]["user_context"] is not None
    assert res.status_code != 200 or res.json().get("status") != "OK"
    assert await count_github_users() == 0


async def test_github_sign_in_uses_custom_validate_access_token_that_accepts(
    fastapi_client: TestClient,
):
    calls: List[str] = []

    async def validate_access_token(
        access_token: str,
        _client_config: ProviderConfigForClient,
        _user_context: Dict[str, Any],
    ):
        calls.append(access_token)

    init_with_github({"validate_access_token": validate_access_token})

    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mock_github_user_info(mocker)

        res = sign_in_up(fastapi_client)

    assert calls == [ACCESS_TOKEN]
    assert res.status_code == 200
    assert res.json()["status"] == "OK"
    assert await count_github_users() == 1


async def get_github_user_info():
    provider = await get_provider("public", "github")
    assert provider is not None
    return await provider.get_user_info({"access_token": ACCESS_TOKEN}, {})


async def test_github_token_check_reports_an_invalid_access_token():
    init_with_github({})

    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mock_github_token_check(mocker, 404, {"message": "Not Found"})

        with raises(Exception, match="Invalid access token"):
            await get_github_user_info()


async def test_github_token_check_reports_rejected_client_credentials_separately_from_an_invalid_access_token():
    init_with_github({})

    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mock_github_token_check(mocker, 401, {"message": "Bad credentials"})

        with raises(Exception, match="client credentials"):
            await get_github_user_info()


async def test_github_token_check_reports_a_missing_client_secret_without_calling_github():
    init_with_github({"clients": [ProviderClientConfig(client_id=CLIENT_ID)]})

    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        token_check = mock_github_token_check(
            mocker, 200, {"app": {"client_id": CLIENT_ID}}
        )

        with raises(Exception, match="client_secret"):
            await get_github_user_info()

    assert not token_check.called


async def test_github_token_check_is_sent_as_json():
    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        token_check = mock_github_token_check(
            mocker, 200, {"app": {"client_id": CLIENT_ID}}
        )

        await default_github_validate_access_token(
            "testaccesstoken",
            ProviderConfigForClient(client_id=CLIENT_ID, client_secret=CLIENT_SECRET),
            {},
        )

    request = cast(httpx.Request, token_check.calls[0].request)  # type: ignore
    assert header_values(request, "content-type") == ["application/json"]
    assert header_values(request, "accept") == ["application/vnd.github+json"]
    assert request.headers["authorization"].startswith("Basic ")
    assert json.loads(request.content) == {"access_token": "testaccesstoken"}
