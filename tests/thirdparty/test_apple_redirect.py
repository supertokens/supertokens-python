import json
from base64 import b64encode
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from pytest import fixture, mark
from starlette.testclient import TestClient
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session, thirdparty

from tests.utils import get_new_core_app_url

pytestmark = mark.asyncio


@fixture(scope="function")
def fastapi_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app, raise_server_exceptions=False)


def init_st(origin: str = "https://app.example.com", **thirdparty_config: Any):
    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="ST",
            api_domain="https://api.example.com",
            origin=origin,
            api_base_path="/auth",
        ),
        framework="fastapi",
        mode="asgi",
        recipe_list=[
            session.init(),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(providers=[]),
                **thirdparty_config,
            ),
        ],
    )


def encode_state(state_obj: Any) -> str:
    return b64encode(json.dumps(state_obj).encode()).decode()


def post_callback(client: TestClient, data: Dict[str, str]):
    return client.post("/auth/callback/apple", data=data, allow_redirects=False)


def assert_rejected(res: Any):
    assert res.status_code == 400
    assert "location" not in res.headers


redirect_uris_on_other_origins: List[str] = [
    "https://evil.test/auth/callback/apple",
    "https://app.example.com@evil.test/auth/callback/apple",
    "https://app.example.com.evil.test/auth/callback/apple",
    "https://evil.test\\@app.example.com/auth/callback/apple",
    "http://app.example.com/auth/callback/apple",
    "https://app.example.com:8443/auth/callback/apple",
    "https://app.example.com:99999/auth/callback/apple",
    "https://app.example.com:abc/auth/callback/apple",
    "https://app.example.com/auth/callback/apple\r\nSet-Cookie: a=b",
    "https://app.exa\tmple.com/auth/callback/apple",
    "/auth/callback/apple",
    "//evil.test/auth/callback/apple",
    "javascript:alert(1)",
    "",
]


@mark.parametrize("frontend_redirect_uri", redirect_uris_on_other_origins)
async def test_apple_redirect_rejects_targets_off_the_configured_origin(
    fastapi_client: TestClient, frontend_redirect_uri: str
):
    init_st()

    res = post_callback(
        fastapi_client,
        {
            "state": encode_state({"frontendRedirectURI": frontend_redirect_uri}),
            "code": "testing",
        },
    )

    assert_rejected(res)


invalid_states: List[Optional[str]] = [
    None,
    "",
    "%%%not-base64%%%",
    b64encode(b"not json").decode(),
    encode_state(["https://app.example.com/auth/callback/apple"]),
    encode_state("https://app.example.com/auth/callback/apple"),
    encode_state({}),
    encode_state({"frontendRedirectURI": 123}),
    encode_state({"frontendRedirectURI": None}),
    encode_state({"frontendRedirectURI": ["https://app.example.com/cb"]}),
]


@mark.parametrize("state", invalid_states)
async def test_apple_redirect_rejects_invalid_state(
    fastapi_client: TestClient, state: Optional[str]
):
    init_st()

    data = {"code": "testing"}
    if state is not None:
        data["state"] = state
    res = post_callback(fastapi_client, data)

    assert_rejected(res)


async def test_apple_redirect_rejects_deeply_nested_state(fastapi_client: TestClient):
    init_st()

    state = b64encode(("[" * 100000 + "]" * 100000).encode()).decode()
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert_rejected(res)


async def test_apple_redirect_to_the_configured_origin(fastapi_client: TestClient):
    init_st()

    state = encode_state(
        {"frontendRedirectURI": "https://app.example.com/auth/callback/apple"}
    )
    res = post_callback(
        fastapi_client, {"state": state, "code": "testcode", "id_token": "testidtoken"}
    )

    assert res.status_code == 303
    assert res.content == b""
    location = urlsplit(res.headers["location"])
    assert (location.scheme, location.netloc, location.path) == (
        "https",
        "app.example.com",
        "/auth/callback/apple",
    )
    assert parse_qs(location.query) == {
        "state": [state],
        "code": ["testcode"],
        "id_token": ["testidtoken"],
    }


async def test_apple_redirect_accepts_url_safe_base64_state(
    fastapi_client: TestClient,
):
    init_st()

    state = (
        encode_state({"frontendRedirectURI": "https://app.example.com/cb?a=b~~~"})
        .replace("+", "-")
        .replace("/", "_")
        .rstrip("=")
    )
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert res.status_code == 303
    assert res.headers["location"].startswith("https://app.example.com/cb?")


@mark.parametrize(
    "origin,frontend_redirect_uri",
    [
        ("https://App.Example.com:443", "https://app.example.com/auth/callback/apple"),
        ("https://app.example.com", "https://APP.example.com:443/auth/callback/apple"),
        ("http://localhost:3000", "http://localhost:3000/auth/callback/apple"),
        ("http://app.example.com", "http://app.example.com:80/auth/callback/apple"),
    ],
)
async def test_apple_redirect_compares_normalised_origins(
    fastapi_client: TestClient, origin: str, frontend_redirect_uri: str
):
    init_st(origin=origin)

    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert res.status_code == 303
    assert parse_qs(urlsplit(res.headers["location"]).query)["code"] == ["testcode"]
