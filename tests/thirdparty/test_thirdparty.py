import datetime
import json
from base64 import b64encode
from typing import Dict, Any, Optional

import respx
from fastapi import FastAPI
from pytest import fixture, mark
from pytest_mock import MockerFixture
from starlette.testclient import TestClient

from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session, thirdparty
from supertokens_python.recipe import thirdpartyemailpassword
from supertokens_python.recipe.thirdparty.provider import (
    ProviderClientConfig,
    ProviderConfig,
    ProviderInput,
    Provider,
    RedirectUriInfo,
    ProviderConfigForClient,
)
from supertokens_python.recipe.thirdparty.types import (
    UserInfo,
    UserInfoEmail,
    RawUserInfoFromProvider,
)
from tests.utils import (
    setup_function,
    teardown_function,
    start_st,
    st_init_common_args,
)

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore
_ = start_st  # type:ignore

pytestmark = mark.asyncio

respx_mock = respx.MockRouter

access_token_validated: bool = False


@fixture(scope="function")
async def fastapi_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app, raise_server_exceptions=False)


async def test_thirdpary_parsing_works(fastapi_client: TestClient):
    st_init_args = {
        **st_init_common_args,
        "recipe_list": [
            session.init(),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[
                        thirdparty.ProviderInput(
                            config=thirdparty.ProviderConfig(
                                third_party_id="apple",
                                clients=[
                                    thirdparty.ProviderClientConfig(
                                        client_id="4398792-io.supertokens.example.service",
                                        additional_config={
                                            "keyId": "7M48Y4RYDL",
                                            "teamId": "YWQCXGJRJL",
                                            "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                                        },
                                    ),
                                ],
                            )
                        ),
                    ]
                )
            ),
        ],
    }
    init(**st_init_args)  # type: ignore
    start_st()

    state = b64encode(
        json.dumps({"frontendRedirectURI": "http://localhost:3000/redirect"}).encode()
    ).decode()
    code = "testing"

    data = {"state": state, "code": code}
    res = fastapi_client.post("/auth/callback/apple", data=data)

    assert res.status_code == 303
    assert res.content == b""
    assert (
        res.headers["location"]
        == f"http://localhost:3000/redirect?state={state.replace('=', '%3D')}&code={code}"
    )


async def exchange_auth_code_for_valid_oauth_tokens(  # pylint: disable=unused-argument
    redirect_uri_info: RedirectUriInfo,
    user_context: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "access_token": "accesstoken",
        "id_token": "idtoken",
    }


async def exchange_auth_code_for_invalid_oauth_tokens(  # pylint: disable=unused-argument
    redirect_uri_info: RedirectUriInfo,
    user_context: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "access_token": "wrongaccesstoken",
        "id_token": "wrongidtoken",
    }


def get_custom_invalid_token_provider(provider: Provider) -> Provider:
    provider.exchange_auth_code_for_oauth_tokens = (
        exchange_auth_code_for_invalid_oauth_tokens
    )
    return provider


def get_custom_valid_token_provider(provider: Provider) -> Provider:
    provider.exchange_auth_code_for_oauth_tokens = (
        exchange_auth_code_for_valid_oauth_tokens
    )
    return provider


async def invalid_access_token(  # pylint: disable=unused-argument
    access_token: str,
    config: ProviderConfigForClient,
    user_context: Optional[Dict[str, Any]],
):
    if access_token == "wrongaccesstoken":
        raise Exception("Invalid access token")


async def valid_access_token(  # pylint: disable=unused-argument
    access_token: str,
    config: ProviderConfigForClient,
    user_context: Optional[Dict[str, Any]],
):
    global access_token_validated
    if access_token == "accesstoken":
        access_token_validated = True
        return
    raise Exception("Unexpected access token")


async def test_signinup_when_validate_access_token_throws(fastapi_client: TestClient):
    st_init_args = {
        **st_init_common_args,
        "recipe_list": [
            session.init(),
            thirdpartyemailpassword.init(
                providers=[
                    ProviderInput(
                        config=ProviderConfig(
                            third_party_id="custom",
                            clients=[
                                ProviderClientConfig(
                                    client_id="test",
                                    client_secret="test-secret",
                                    scope=["profile", "email"],
                                ),
                            ],
                            authorization_endpoint="https://example.com/oauth/authorize",
                            validate_access_token=invalid_access_token,
                            authorization_endpoint_query_params={
                                "response_type": "token",  # Changing an existing parameter
                                "response_mode": "form",  # Adding a new parameter
                                "scope": None,  # Removing a parameter
                            },
                            token_endpoint="https://example.com/oauth/token",
                        ),
                        override=get_custom_invalid_token_provider,
                    )
                ]
            ),
        ],
    }
    init(**st_init_args)  # type: ignore
    start_st()

    res = fastapi_client.post(
        "/auth/signinup",
        json={
            "thirdPartyId": "custom",
            "redirectURIInfo": {
                "redirectURIOnProviderDashboard": "http://127.0.0.1/callback",
                "redirectURIQueryParams": {
                    "code": "abcdefghj",
                },
            },
        },
    )
    assert res.status_code == 500


async def test_signinup_works_when_validate_access_token_does_not_throw(
    fastapi_client: TestClient, mocker: MockerFixture
):
    time = str(datetime.datetime.now())
    mocker.patch(
        "supertokens_python.recipe.thirdparty.providers.custom.get_supertokens_user_info_result_from_raw_user_info",
        return_value=UserInfo(
            "" + time,
            UserInfoEmail(f"johndoeprovidertest+{time}@supertokens.com", True),
            RawUserInfoFromProvider({}, {}),
        ),
    )

    st_init_args = {
        **st_init_common_args,
        "recipe_list": [
            session.init(),
            thirdpartyemailpassword.init(
                providers=[
                    ProviderInput(
                        config=ProviderConfig(
                            third_party_id="custom",
                            clients=[
                                ProviderClientConfig(
                                    client_id="test",
                                    client_secret="test-secret",
                                    scope=["profile", "email"],
                                ),
                            ],
                            authorization_endpoint="https://example.com/oauth/authorize",
                            validate_access_token=valid_access_token,
                            authorization_endpoint_query_params={
                                "response_type": "token",  # Changing an existing parameter
                                "response_mode": "form",  # Adding a new parameter
                                "scope": None,  # Removing a parameter
                            },
                            token_endpoint="https://example.com/oauth/token",
                        ),
                        override=get_custom_valid_token_provider,
                    )
                ]
            ),
        ],
    }

    init(**st_init_args)  # type: ignore
    start_st()

    res = fastapi_client.post(
        "/auth/signinup",
        json={
            "thirdPartyId": "custom",
            "redirectURIInfo": {
                "redirectURIOnProviderDashboard": "http://127.0.0.1/callback",
                "redirectURIQueryParams": {
                    "code": "abcdefghj",
                },
            },
        },
    )

    assert res.status_code == 200
    assert access_token_validated is True
    assert res.json()["status"] == "OK"


async def test_signinup_android_without_redirect_uri(
    fastapi_client: TestClient, mocker: MockerFixture
):
    time = str(datetime.datetime.now())
    mocker.patch(
        "supertokens_python.recipe.thirdparty.providers.custom.get_supertokens_user_info_result_from_raw_user_info",
        return_value=UserInfo(
            "" + time,
            UserInfoEmail(f"johndoeprovidertest+{time}@supertokens.com", True),
            RawUserInfoFromProvider({}, {}),
        ),
    )
    st_init_args = {
        **st_init_common_args,
        "recipe_list": [
            session.init(),
            thirdpartyemailpassword.init(
                providers=[
                    ProviderInput(
                        config=ProviderConfig(
                            third_party_id="custom",
                            clients=[
                                ProviderClientConfig(
                                    client_id="test",
                                    client_secret="test-secret",
                                    scope=["profile", "email"],
                                    client_type="android",
                                ),
                            ],
                            authorization_endpoint="https://example.com/oauth/authorize",
                            authorization_endpoint_query_params={
                                "response_type": "token",  # Changing an existing parameter
                                "response_mode": "form",  # Adding a new parameter
                                "scope": None,  # Removing a parameter
                            },
                            token_endpoint="https://example.com/oauth/token",
                        ),
                    )
                ]
            ),
        ],
    }
    init(**st_init_args)  # type: ignore
    start_st()

    res = fastapi_client.post(
        "/auth/signinup",
        json={
            "thirdPartyId": "custom",
            "clientType": "android",
            "oAuthTokens": {
                "access_token": "accesstoken",
                "id_token": "idtoken",
            },
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "OK"
