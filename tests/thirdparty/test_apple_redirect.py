import json
from base64 import b64encode
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi import FastAPI
from pytest import fixture, mark, raises
from starlette.testclient import TestClient
from starlette.types import Message
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.exceptions import BadInputError
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session, thirdparty
from supertokens_python.recipe.thirdparty.api.implementation import (
    get_frontend_redirect_uri_from_state,
)
from supertokens_python.recipe.thirdparty.utils import (
    get_normalised_origin_tuple,
    is_http_url_with_userinfo,
    normalise_frontend_redirect_uri,
)

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
        ("HTTPS://App.Example.com/a/../cb", "https://app.example.com/cb"),
        ("https://app.example.com/a/%2e%2E/cb?x=1", "https://app.example.com/cb?x=1"),
        ("myapp://Callback/../x", "myapp://Callback/x"),
        ("com.example.app:/a/../oauth2redirect", "com.example.app:/oauth2redirect"),
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


@mark.parametrize(
    "frontend_redirect_uri,expected_location",
    [
        ("https://app.example.com/a/../cb", "https://app.example.com/cb?{}"),
        ("https://app.example.com/a/%2E%2e/b/./cb", "https://app.example.com/b/cb?{}"),
        ("https://app.example.com/cb?", "https://app.example.com/cb?{}"),
        ("https://app.example.com/cb#", "https://app.example.com/cb?{}#"),
    ],
)
async def test_apple_redirect_removes_dot_segments_from_the_target(
    fastapi_client: TestClient, frontend_redirect_uri: str, expected_location: str
):
    init_st()

    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert res.status_code == 303
    assert res.headers["location"] == expected_location.format(
        urlencode({"state": state, "code": "testcode"})
    )


@mark.parametrize(
    "frontend_redirect_uri,normalised_uri",
    [
        ("https://app.example.com", "https://app.example.com/"),
        ("HTTPS://App.Example.com:443/cb", "https://app.example.com/cb"),
        ("HTTPS://App.Example.com/a/../cb", "https://app.example.com/cb"),
        ("https://app.example.com/a/%2e%2e/cb", "https://app.example.com/cb"),
        ("https://app.example.com/a/%2E%2e/cb", "https://app.example.com/cb"),
        ("https://app.example.com/a/.%2e/cb", "https://app.example.com/cb"),
        ("https://app.example.com/a/%2e./cb", "https://app.example.com/cb"),
        ("https://app.example.com/a/./%2e/cb", "https://app.example.com/a/cb"),
        ("https://app.example.com/a/b/..", "https://app.example.com/a/"),
        ("https://app.example.com/a/b/%2e", "https://app.example.com/a/b/"),
        ("https://app.example.com/../../cb", "https://app.example.com/cb"),
        ("https://app.example.com/a//../b", "https://app.example.com/a/b"),
        (
            "https://app.example.com/a/..%2fb/...",
            "https://app.example.com/a/..%2fb/...",
        ),
        (
            "https://app.example.com/a/../cb?x=/../y#/../z",
            "https://app.example.com/cb?x=/../y#/../z",
        ),
        ("https://[::1]:8443/a/../b", "https://[::1]:8443/b"),
        ("https://app.example.com/cb?", "https://app.example.com/cb?"),
        ("https://app.example.com/cb#", "https://app.example.com/cb#"),
        ("https://app.example.com?#", "https://app.example.com/?#"),
        ("myapp://Callback/../x", "myapp://Callback/x"),
        ("myapp://Callback/a/%2e%2e/x", "myapp://Callback/x"),
        ("myapp://Callback/a/b/../..", "myapp://Callback/"),
        ("myapp:///a/../callback", "myapp:///callback"),
        ("myapp://host/.//x", "myapp://host//x"),
        ("com.example.app:/a/../oauth2redirect", "com.example.app:/oauth2redirect"),
        ("com.example.app:/a/..//evil/x", "com.example.app:/.//evil/x"),
        ("com.example.app:/.//evil/x", "com.example.app:/.//evil/x"),
        ("myapp:callback/../x", "myapp:callback/../x"),
        ("myapp://Callback?", "myapp://Callback?"),
        ("myapp:callback#", "myapp:callback#"),
        (
            "intent://callback/../x#Intent;package=com.example.app;end",
            "intent://callback/x#Intent;package=com.example.app;end",
        ),
    ],
)
def test_normalise_frontend_redirect_uri(
    frontend_redirect_uri: str, normalised_uri: str
):
    assert normalise_frontend_redirect_uri(frontend_redirect_uri) == normalised_uri
    # Normalising again doesn't change it
    assert normalise_frontend_redirect_uri(normalised_uri) == normalised_uri


@mark.parametrize(
    "origin,frontend_redirect_uri",
    [
        ("https://bücher.example", "https://xn--bcher-kva.example/auth/callback/apple"),
        ("https://BÜCHER.example:443", "https://xn--bcher-kva.example/cb"),
        ("https://xn--bcher-kva.example", "https://XN--BCHER-KVA.example/cb"),
    ],
)
async def test_apple_redirect_compares_internationalised_origins_in_punycode_form(
    fastapi_client: TestClient, origin: str, frontend_redirect_uri: str
):
    init_st(origin=origin)

    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert res.status_code == 303
    location = urlsplit(res.headers["location"])
    assert location.netloc == "xn--bcher-kva.example"
    assert parse_qs(location.query)["code"] == ["testcode"]


@mark.parametrize(
    "origin,frontend_redirect_uri",
    [
        ("https://bücher.example", "https://bücher.example/cb"),
        ("https://bücher.example", "https://xn--bcher-kva.example.evil.test/cb"),
        ("https://bücher.example", "http://xn--bcher-kva.example/cb"),
    ],
)
async def test_apple_redirect_rejects_targets_off_an_internationalised_origin(
    fastapi_client: TestClient, origin: str, frontend_redirect_uri: str
):
    init_st(origin=origin)

    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert_rejected(res)


@mark.parametrize(
    "url,convert_idn_host,expected",
    [
        ("https://App.Example.com", False, ("https", "app.example.com", 443)),
        ("https://App.Example.com", True, ("https", "app.example.com", 443)),
        ("https://bücher.example", False, None),
        ("https://bücher.example", True, ("https", "xn--bcher-kva.example", 443)),
        ("http://BÜCHER.example:8080/x", True, ("http", "xn--bcher-kva.example", 8080)),
        (
            "https://xn--bcher-kva.example",
            False,
            ("https", "xn--bcher-kva.example", 443),
        ),
        (f"https://{'ü' * 64}.example", True, None),
        ("https://user@bücher.example", True, None),
        ("myapp://bücher.example", True, None),
    ],
)
def test_get_normalised_origin_tuple_converts_idn_hosts_only_if_asked(
    url: str, convert_idn_host: bool, expected: Optional[Tuple[str, str, int]]
):
    assert (
        get_normalised_origin_tuple(url, convert_idn_host=convert_idn_host) == expected
    )


redirect_uris_with_lone_surrogates: List[str] = [
    "https://app.example.com/cb\ud800",
    "https://app.example.com/cb?next=\udfff",
    "https://app.example.com/cb#\ud800",
    "myapp://callback/\ud800",
]


@mark.parametrize("frontend_redirect_uri", redirect_uris_with_lone_surrogates)
def test_get_frontend_redirect_uri_from_state_rejects_lone_surrogates(
    frontend_redirect_uri: str,
):
    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})

    with raises(BadInputError):
        get_frontend_redirect_uri_from_state(state)


@mark.parametrize("frontend_redirect_uri", redirect_uris_with_lone_surrogates[:3])
async def test_apple_redirect_rejects_lone_surrogates(
    fastapi_client: TestClient, frontend_redirect_uri: str
):
    init_st()

    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert_rejected(res)


@mark.parametrize("frontend_redirect_uri", redirect_uris_with_lone_surrogates)
async def test_apple_redirect_custom_check_is_not_called_for_lone_surrogates(
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
    "frontend_redirect_uri",
    [
        "https://user@app.example.com/cb",
        "https://user:password@app.example.com/cb",
        "https://:password@app.example.com/cb",
        "HTTP://app.example.com@evil.test/cb",
    ],
)
@mark.parametrize("with_custom_check", [False, True])
async def test_apple_redirect_names_userinfo_as_the_reason_for_rejecting(
    fastapi_client: TestClient, frontend_redirect_uri: str, with_custom_check: bool
):
    calls: List[str] = []

    async def is_valid_frontend_redirect_uri(
        frontend_redirect_uri: str, request: Any, user_context: Dict[str, Any]
    ) -> bool:
        calls.append(frontend_redirect_uri)
        return True

    if with_custom_check:
        init_st(is_valid_frontend_redirect_uri=is_valid_frontend_redirect_uri)
    else:
        init_st()

    state = encode_state({"frontendRedirectURI": frontend_redirect_uri})
    res = post_callback(fastapi_client, {"state": state, "code": "testcode"})

    assert_rejected(res)
    assert res.json() == {
        "message": "frontendRedirectURI in state must not contain a username or password"
    }
    assert calls == []


@mark.parametrize(
    "url,expected",
    [
        ("https://user@app.example.com/cb", True),
        ("http://user:password@app.example.com/cb", True),
        ("https://@app.example.com/cb", True),
        ("https://app.example.com/cb?a=b@c#d@e", False),
        ("https://evil.test\\@app.example.com/cb", False),
        ("https://user@app.example.com/c b", False),
        ("myapp://user@callback", False),
        ("https://[::1/cb", False),
    ],
)
def test_is_http_url_with_userinfo(url: str, expected: bool):
    assert is_http_url_with_userinfo(url) is expected
