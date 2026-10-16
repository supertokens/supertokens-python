import json
from base64 import b64encode
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi import FastAPI
from pytest import fixture, mark
from starlette.testclient import TestClient
from starlette.types import Message
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


async def post_callback_without_client(
    data: Dict[str, str],
) -> Tuple[int, Dict[str, str]]:
    """
    Calls the ASGI app directly: the test client always parses the Location header of a
    redirect, which fails for valid custom-scheme URLs like `myapp:callback`.
    """
    app = FastAPI()
    app.add_middleware(get_middleware())

    body = urlencode(data).encode()
    scope: Dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/auth/callback/apple",
        "raw_path": b"/auth/callback/apple",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"api.example.com"),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("api.example.com", 443),
    }
    request_sent = False
    messages: List[Message] = []

    async def receive() -> Message:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        messages.append(message)

    await app(scope, receive, send)

    start = next(m for m in messages if m["type"] == "http.response.start")
    headers = {k.decode().lower(): v.decode() for k, v in start["headers"]}
    return start["status"], headers


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
    "myapp://callback",
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


async def test_apple_redirect_custom_check_can_allow_another_origin(
    fastapi_client: TestClient,
):
    calls: List[Any] = []

    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        calls.append((frontend_redirect_uri, request, user_context))
        return frontend_redirect_uri.startswith("https://other.example.com/")

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state({"frontendRedirectURI": "https://other.example.com/cb"})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert res.status_code == 303
    location = urlsplit(res.headers["location"])
    assert location.netloc == "other.example.com"
    assert parse_qs(location.query)["code"] == ["testcode"]
    assert len(calls) == 1
    assert calls[0][0] == "https://other.example.com/cb"
    assert calls[0][1] is not None
    assert isinstance(calls[0][2], dict)


async def test_apple_redirect_custom_check_can_block_the_configured_origin(
    fastapi_client: TestClient,
):
    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        return False

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state(
        {"frontendRedirectURI": "https://app.example.com/auth/callback/apple"}
    )
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert_rejected(res)


async def test_apple_redirect_custom_check_can_be_sync(fastapi_client: TestClient):
    def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        return True

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state({"frontendRedirectURI": "https://other.example.com/cb"})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert res.status_code == 303
    assert urlsplit(res.headers["location"]).netloc == "other.example.com"


async def test_apple_redirect_custom_check_only_allows_on_true(
    fastapi_client: TestClient,
):
    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> Any:
        return "yes"

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state({"frontendRedirectURI": "https://other.example.com/cb"})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert_rejected(res)


async def test_apple_redirect_custom_check_errors_propagate(
    fastapi_client: TestClient,
):
    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        raise Exception("check failed")

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state(
        {"frontendRedirectURI": "https://app.example.com/auth/callback/apple"}
    )
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert res.status_code == 500
    assert "location" not in res.headers


@mark.parametrize(
    "frontend_redirect_uri",
    [
        "myapp://callback",
        "myapp:callback",
        "com.example.app:/oauth2redirect",
        "intent://callback#Intent;package=com.example.app;scheme=signinwithapple;end",
    ],
)
async def test_apple_redirect_custom_check_can_allow_custom_scheme_targets(
    frontend_redirect_uri: str,
):
    calls: List[str] = []

    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        calls.append(frontend_redirect_uri)
        return True

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})
    status, headers = await post_callback_without_client(
        {"state": state, "code": "testcode"}
    )

    assert status == 303
    assert calls == [frontend_redirect_uri]
    target = urlsplit(frontend_redirect_uri)
    location = urlsplit(headers["location"])
    assert (location.scheme, location.netloc, location.path, location.fragment) == (
        target.scheme,
        target.netloc,
        target.path,
        target.fragment,
    )
    assert parse_qs(location.query) == {"state": [state], "code": ["testcode"]}


async def test_apple_redirect_custom_check_keeps_the_fragment_after_the_query(
    fastapi_client: TestClient,
):
    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        return True

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state(
        {
            "frontendRedirectURI": "intent://callback#Intent;package=com.example.app;scheme=signinwithapple;end"
        }
    )
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert res.status_code == 303
    assert res.headers["location"].startswith("intent://callback?")
    assert res.headers["location"].endswith(
        "#Intent;package=com.example.app;scheme=signinwithapple;end"
    )


@mark.parametrize(
    "frontend_redirect_uri",
    [
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "blob:https://app.example.com/x",
        "about:blank",
        "filesystem:https://app.example.com/temporary/x",
        "/auth/callback/apple",
        "//evil.test/cb",
        "https:///auth/callback/apple",
        "https://evil.test\\@app.example.com/auth/callback/apple",
        "https://app.example.com@evil.test/auth/callback/apple",
        "myapp://callback\r\nSet-Cookie: a=b",
    ],
)
async def test_apple_redirect_custom_check_is_not_called_for_disallowed_targets(
    fastapi_client: TestClient, frontend_redirect_uri: str
):
    calls: List[str] = []

    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        calls.append(frontend_redirect_uri)
        return True

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert_rejected(res)
    assert calls == []


@mark.parametrize(
    "frontend_redirect_uri,normalised_uri",
    [
        ("https://app.example.com", "https://app.example.com/"),
        ("HTTPS://App.Example.com:443/cb", "https://app.example.com/cb"),
        (
            "https://app.example.com:8443/cb?a=b#f",
            "https://app.example.com:8443/cb?a=b#f",
        ),
        ("MyApp://Callback/x", "myapp://Callback/x"),
        ("myapp:///callback", "myapp:///callback"),
    ],
)
async def test_apple_redirect_custom_check_gets_the_normalised_uri_that_is_redirected_to(
    frontend_redirect_uri: str, normalised_uri: str
):
    calls: List[str] = []

    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        calls.append(frontend_redirect_uri)
        return True

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})
    status, headers = await post_callback_without_client(
        {"state": state, "code": "testcode"}
    )

    assert status == 303
    assert calls == [normalised_uri]
    url, _, fragment = normalised_uri.partition("#")
    assert headers["location"].startswith(url.partition("?")[0] + "?")
    assert headers["location"].endswith(f"#{fragment}" if fragment else "code=testcode")


async def test_apple_redirect_keeps_the_existing_query_of_the_target(
    fastapi_client: TestClient,
):
    init_st()

    state = encode_state(
        {
            "frontendRedirectURI": "https://app.example.com/cb?flag=&a=b%20c&code=old&a=d+e&st%61te=x#frag"
        }
    )
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert res.status_code == 303
    assert res.headers["location"] == (
        "https://app.example.com/cb?flag=&a=b%20c&a=d+e&state="
        + state.replace("=", "%3D")
        + "&code=testcode#frag"
    )


@mark.parametrize(
    "frontend_redirect_uri,expected_location_start",
    [
        (
            "https://app.example.com/cb?next=日本",
            "https://app.example.com/cb?next=%E6%97%A5%E6%9C%AC&",
        ),
        (
            "https://app.example.com/パス?next=%E6%97%A5",
            "https://app.example.com/%E3%83%91%E3%82%B9?next=%E6%97%A5&",
        ),
    ],
)
async def test_apple_redirect_percent_encodes_non_ascii_characters(
    fastapi_client: TestClient, frontend_redirect_uri: str, expected_location_start: str
):
    init_st()

    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert res.status_code == 303
    assert res.headers["location"].startswith(expected_location_start)


async def test_apple_redirect_custom_check_gets_non_ascii_characters_percent_encoded():
    calls: List[str] = []

    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        calls.append(frontend_redirect_uri)
        return True

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state({"frontendRedirectURI": "myapp://cb?x=日本#片"})
    status, headers = await post_callback_without_client(
        {"state": state, "code": "testcode"}
    )

    assert status == 303
    assert calls == ["myapp://cb?x=%E6%97%A5%E6%9C%AC#%E7%89%87"]
    assert headers["location"] == (
        "myapp://cb?x=%E6%97%A5%E6%9C%AC&"
        + urlencode({"state": state, "code": "testcode"})
        + "#%E7%89%87"
    )


async def test_apple_redirect_rejects_non_ascii_hosts(fastapi_client: TestClient):
    calls: List[str] = []

    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        calls.append(frontend_redirect_uri)
        return True

    init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)

    state = encode_state({"frontendRedirectURI": "https://日本.example/cb"})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert_rejected(res)
    assert calls == []
