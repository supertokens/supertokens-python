import json
import time
from typing import Any, Dict, Iterator, Optional

import httpx
import jwt
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from jwt.algorithms import RSAAlgorithm
from pytest import fixture, mark
from starlette.testclient import TestClient
from supertokens_python import init
from supertokens_python.asyncio import list_users_by_account_info
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session, thirdparty
from supertokens_python.recipe.thirdparty.provider import (
    ProviderClientConfig,
    ProviderConfig,
    ProviderInput,
)
from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo
from supertokens_python.types.base import AccountInfoInput

from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

IDP = "https://google-workspaces-idp.test"
CLIENT_ID = "workspaces-client"

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_jwk: Dict[str, Any] = {
    **json.loads(RSAAlgorithm.to_jwk(private_key.public_key())),
    "kid": "test-key",
    "alg": "RS256",
    "use": "sig",
}


@fixture(scope="function")
def fastapi_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app, raise_server_exceptions=False)


@fixture(scope="function")
def idp() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_mocked=False, assert_all_called=False) as mocker:
        mocker.route(host="localhost").pass_through()
        mocker.get(f"{IDP}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": IDP,
                    "authorization_endpoint": f"{IDP}/auth",
                    "token_endpoint": f"{IDP}/token",
                    "userinfo_endpoint": f"{IDP}/userinfo",
                    "jwks_uri": f"{IDP}/jwks",
                },
            )
        )
        mocker.get(f"{IDP}/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [public_jwk]})
        )
        yield mocker


def setup(hd: Optional[str]):
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(get_token_transfer_method=lambda *_: "header"),  # type: ignore
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=[
                            ProviderInput(
                                config=ProviderConfig(
                                    third_party_id="google-workspaces",
                                    oidc_discovery_endpoint=f"{IDP}/.well-known/openid-configuration",
                                    clients=[
                                        ProviderClientConfig(
                                            client_id=CLIENT_ID,
                                            client_secret="secret",
                                            additional_config=None
                                            if hd is None
                                            else {"hd": hd},
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


def mock_user_info(idp: respx.MockRouter, user_info: Dict[str, Any]):
    idp.get(f"{IDP}/userinfo").mock(return_value=httpx.Response(200, json=user_info))


def create_id_token(sub: str, **claims: Any) -> str:
    now = int(time.time())
    payload: Dict[str, Any] = {
        "iss": IDP,
        "aud": CLIENT_ID,
        "sub": sub,
        "iat": now,
        "exp": now + 600,
        "email": f"{sub}@corp.example",
        "email_verified": True,
        **claims,
    }
    return jwt.encode(
        payload, private_key, algorithm="RS256", headers={"kid": "test-key"}
    )


def sign_in_up(fastapi_client: TestClient, oauth_tokens: Dict[str, Any]):
    return fastapi_client.post(
        "/auth/signinup",
        json={"thirdPartyId": "google-workspaces", "oAuthTokens": oauth_tokens},
    )


async def get_users(sub: str):
    return await list_users_by_account_info(
        "public",
        AccountInfoInput(third_party=ThirdPartyInfo(sub, "google-workspaces")),
    )


def is_ok(res: httpx.Response) -> bool:
    return res.status_code == 200 and res.json().get("status") == "OK"


async def test_access_token_only_sign_in_up_rejects_user_without_hd(
    fastapi_client: TestClient, idp: respx.MockRouter
):
    setup("corp.example")
    mock_user_info(
        idp, {"sub": "outsider", "email": "outsider@gmail.com", "email_verified": True}
    )

    res = sign_in_up(fastapi_client, {"access_token": "access-token"})

    assert not is_ok(res)
    assert len(await get_users("outsider")) == 0


async def test_access_token_only_sign_in_up_rejects_user_of_another_domain(
    fastapi_client: TestClient, idp: respx.MockRouter
):
    setup("corp.example")
    mock_user_info(
        idp,
        {
            "sub": "other",
            "email": "other@other.example",
            "email_verified": True,
            "hd": "other.example",
        },
    )

    res = sign_in_up(fastapi_client, {"access_token": "access-token"})

    assert not is_ok(res)
    assert len(await get_users("other")) == 0


async def test_access_token_only_sign_in_up_accepts_user_info_with_matching_hd(
    fastapi_client: TestClient, idp: respx.MockRouter
):
    setup("corp.example")
    mock_user_info(
        idp,
        {
            "sub": "member",
            "email": "member@corp.example",
            "email_verified": True,
            "hd": "corp.example",
        },
    )

    res = sign_in_up(fastapi_client, {"access_token": "access-token"})

    assert is_ok(res)
    assert len(await get_users("member")) == 1


async def test_sign_in_up_accepts_id_token_with_matching_hd(
    fastapi_client: TestClient, idp: respx.MockRouter
):
    setup("corp.example")
    mock_user_info(
        idp, {"sub": "member", "email": "member@corp.example", "email_verified": True}
    )

    res = sign_in_up(
        fastapi_client,
        {
            "access_token": "access-token",
            "id_token": create_id_token("member", hd="corp.example"),
        },
    )

    assert is_ok(res)
    assert len(await get_users("member")) == 1


async def test_id_token_only_sign_in_up_accepts_matching_hd(
    fastapi_client: TestClient, idp: respx.MockRouter
):
    setup("corp.example")

    res = sign_in_up(
        fastapi_client, {"id_token": create_id_token("member", hd="corp.example")}
    )

    assert is_ok(res)
    assert len(await get_users("member")) == 1


async def test_sign_in_up_rejects_id_token_with_another_hd(
    fastapi_client: TestClient, idp: respx.MockRouter
):
    setup("corp.example")
    mock_user_info(
        idp,
        {
            "sub": "other",
            "email": "other@other.example",
            "email_verified": True,
            "hd": "corp.example",
        },
    )

    res = sign_in_up(
        fastapi_client,
        {
            "access_token": "access-token",
            "id_token": create_id_token("other", hd="other.example"),
        },
    )

    assert not is_ok(res)
    assert len(await get_users("other")) == 0


async def test_access_token_only_sign_in_up_accepts_any_domain_with_wildcard_hd(
    fastapi_client: TestClient, idp: respx.MockRouter
):
    setup("*")
    mock_user_info(
        idp, {"sub": "anyone", "email": "anyone@gmail.com", "email_verified": True}
    )

    res = sign_in_up(fastapi_client, {"access_token": "access-token"})

    assert is_ok(res)


async def test_access_token_only_sign_in_up_accepts_any_domain_without_hd_config(
    fastapi_client: TestClient, idp: respx.MockRouter
):
    setup(None)
    mock_user_info(
        idp, {"sub": "anyone", "email": "anyone@gmail.com", "email_verified": True}
    )

    res = sign_in_up(fastapi_client, {"access_token": "access-token"})

    assert is_ok(res)
