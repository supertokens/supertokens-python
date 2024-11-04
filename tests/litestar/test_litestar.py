# pyright: reportUnknownMemberType=false, reportGeneralTypeIssues=false
from __future__ import annotations
import json
from typing import Any, Dict, Union

from litestar import get, post, Litestar, Request, MediaType
from litestar.di import Provide
from litestar.testing import TestClient
from pytest import fixture, mark, skip

from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework import BaseRequest
from supertokens_python.framework.litestar import get_middleware
from supertokens_python.querier import Querier
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe import thirdparty
from supertokens_python.recipe.dashboard import DashboardRecipe, InputOverrideConfig
from supertokens_python.recipe.dashboard.interfaces import RecipeInterface
from supertokens_python.recipe.dashboard.utils import DashboardConfig
from supertokens_python.recipe.emailpassword.interfaces import (
    APIInterface as EPAPIInterface,
)
from supertokens_python.recipe.emailpassword.interfaces import APIOptions
from supertokens_python.recipe.passwordless import PasswordlessRecipe, ContactConfig
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import (
    create_new_session,
    get_session,
    refresh_session,
)
from supertokens_python.recipe.session.exceptions import UnauthorisedError
from supertokens_python.recipe.session.framework.litestar import verify_session
from supertokens_python.recipe.session.interfaces import APIInterface
from supertokens_python.recipe.session.interfaces import APIOptions as SessionAPIOptions
from supertokens_python.utils import is_version_gte
from tests.utils import (
    TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH,
    TEST_DRIVER_CONFIG_COOKIE_DOMAIN,
    TEST_DRIVER_CONFIG_COOKIE_SAME_SITE,
    TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH,
    assert_info_clears_tokens,
    clean_st,
    extract_all_cookies,
    extract_info,
    get_st_init_args,
    reset,
    setup_st,
    start_st,
    create_users,
)


def get_token_transfer_method(*args: Any) -> Any:
    return "cookie"


def override_dashboard_functions(original_implementation: RecipeInterface):
    def should_allow_access(
            request: BaseRequest, __: DashboardConfig, ___: Dict[str, Any]
    ):
        auth_header = request.get_header("authorization")
        return auth_header == "Bearer testapikey"

    original_implementation.should_allow_access = should_allow_access
    return original_implementation


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@fixture(scope="function")
def litestar_test_client() -> TestClient[Litestar]:
    @get("/login")
    async def login(request: Request[Any, Any, Any]) -> dict[str, Any]:
        user_id = "userId"
        await create_new_session(request, user_id, {}, {})
        return {"userId": user_id}

    @post("/refresh")
    async def custom_refresh(request: Request[Any, Any, Any]) -> dict[str, Any]:
        await refresh_session(request)
        return {}

    @get("/info")
    async def info_get(request: Request[Any, Any, Any]) -> dict[str, Any]:
        await get_session(request, True)
        return {}

    @get("/custom/info")
    def custom_info() -> dict[str, Any]:
        return {}

    @get("/handle")
    async def handle_get(request: Request[Any, Any, Any]) -> dict[str, Any]:
        session: Union[None, SessionContainer] = await get_session(request, True)
        if session is None:
            raise RuntimeError("Should never come here")
        return {"s": session.get_handle()}

    @get(
        "/handle-session-optional",
        dependencies={"session": Provide(verify_session(session_required=False))},
    )
    def handle_get_optional(session: SessionContainer) -> dict[str, Any]:

        if session is None:
            return {"s": "empty session"}

        return {"s": session.get_handle()}

    @post("/logout")
    async def custom_logout(request: Request[Any, Any, Any]) -> dict[str, Any]:
        session: Union[None, SessionContainer] = await get_session(request, True)
        if session is None:
            raise RuntimeError("Should never come here")
        await session.revoke_session()
        return {}

    @post("/create", media_type=MediaType.TEXT)
    async def _create(request: Request[Any, Any, Any]) -> str:
        await create_new_session(request, "userId", {}, {})
        return ""

    @post("/create-throw")
    async def _create_throw(request: Request[Any, Any, Any]) -> None:
        await create_new_session(request, "userId", {}, {})
        raise UnauthorisedError("unauthorised")

    app = Litestar(
        route_handlers=[
            login,
            custom_logout,
            custom_refresh,
            custom_info,
            info_get,
            handle_get,
            handle_get_optional,
            _create,
            _create_throw,
        ],
        middleware=[get_middleware()],
    )

    return TestClient(app)


def apis_override_session(param: APIInterface):
    param.disable_refresh_post = True
    return param


def test_login_refresh(litestar_test_client: TestClient[Litestar]):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
                override=session.InputOverrideConfig(apis=apis_override_session),
            )
        ],
        mode="asgi",
    )
    start_st()

    with litestar_test_client as client:
        response_1 = client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert (
            cookies_1["sAccessToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
            cookies_1["sRefreshToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )

    with litestar_test_client as client:
        response_3 = client.post(
            url="/refresh",
            headers={"anti-csrf": response_1.headers.get("anti-csrf")},
            cookies={
                "sRefreshToken": cookies_1["sRefreshToken"]["value"],
            },
        )
    cookies_3 = extract_all_cookies(response_3)

    assert cookies_3["sAccessToken"]["value"] != cookies_1["sAccessToken"]["value"]
    assert cookies_3["sRefreshToken"]["value"] != cookies_1["sRefreshToken"]["value"]
    assert response_3.headers.get("anti-csrf") is not None
    assert cookies_3["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_3["sAccessToken"]["httponly"]
    assert cookies_3["sRefreshToken"]["httponly"]
    assert (
            cookies_3["sAccessToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
            cookies_3["sRefreshToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )


def test_login_logout(litestar_test_client: TestClient[Litestar]):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            )
        ],
        mode="asgi",
    )
    start_st()

    with litestar_test_client as client:
        response_1 = client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert (
            cookies_1["sAccessToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
            cookies_1["sRefreshToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None

    with litestar_test_client as client:
        response_2 = client.post(
            url="/logout",
            headers={"anti-csrf": response_1.headers.get("anti-csrf")},
            cookies={
                "sAccessToken": cookies_1["sAccessToken"]["value"],
            },
        )
    cookies_2 = extract_all_cookies(response_2)
    assert response_2.headers.get("anti-csrf") is None
    assert cookies_2["sAccessToken"]["value"] == ""
    assert cookies_2["sRefreshToken"]["value"] == ""
    assert cookies_2["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2["sAccessToken"]["httponly"]
    assert cookies_2["sRefreshToken"]["httponly"]
    assert (
            cookies_2["sAccessToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
            cookies_2["sRefreshToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_2["sAccessToken"]["secure"] is None
    assert cookies_2["sRefreshToken"]["secure"] is None


def test_login_info(litestar_test_client: TestClient[Litestar]):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            )
        ],
        mode="asgi",
    )
    start_st()

    with litestar_test_client as client:
        response_1 = client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert (
            cookies_1["sAccessToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
            cookies_1["sRefreshToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None

    with litestar_test_client as client:
        response_2 = client.get(
            url="/info",
            headers={"anti-csrf": response_1.headers.get("anti-csrf")},
            cookies={
                "sAccessToken": cookies_1["sAccessToken"]["value"],
            },
        )
    cookies_2 = extract_all_cookies(response_2)
    assert not cookies_2


def test_login_handle(litestar_test_client: TestClient[Litestar]):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            )
        ],
        mode="asgi",
    )
    start_st()

    with litestar_test_client as client:
        response_1 = client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert (
            cookies_1["sAccessToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
            cookies_1["sRefreshToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None

    with litestar_test_client as client:
        response_2 = client.get(
            url="/handle",
            headers={"anti-csrf": response_1.headers.get("anti-csrf")},
            cookies={
                "sAccessToken": cookies_1["sAccessToken"]["value"],
            },
        )
    result_dict = json.loads(response_2.content)
    assert "s" in result_dict


def test_login_refresh_error_handler(litestar_test_client: TestClient[Litestar]):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            )
        ],
        mode="asgi",
    )
    start_st()

    with litestar_test_client as client:
        response_1 = client.get("/login")
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get("anti-csrf") is not None
    assert cookies_1["sAccessToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sRefreshToken"]["domain"] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1["sAccessToken"]["path"] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1["sRefreshToken"]["path"] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1["sAccessToken"]["httponly"]
    assert cookies_1["sRefreshToken"]["httponly"]
    assert (
            cookies_1["sAccessToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert (
            cookies_1["sRefreshToken"]["samesite"].lower()
            == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    )
    assert cookies_1["sAccessToken"]["secure"] is None
    assert cookies_1["sRefreshToken"]["secure"] is None

    with litestar_test_client as client:
        response_3 = client.post(
            url="/refresh",
            headers={"anti-csrf": response_1.headers.get("anti-csrf")},
            cookies={
                # no cookies
            },
        )
    assert response_3.status_code == 401  # not authorized because no refresh tokens


def test_custom_response(litestar_test_client: TestClient[Litestar]):
    def override_email_password_apis(original_implementation: EPAPIInterface):
        original_func = original_implementation.email_exists_get

        async def email_exists_get(
                email: str, api_options: APIOptions, user_context: Dict[str, Any]
        ):
            response_dict = {"custom": True}
            api_options.response.set_status_code(203)
            api_options.response.set_json_content(response_dict)
            return await original_func(email, api_options, user_context)

        original_implementation.email_exists_get = email_exists_get
        return original_implementation

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            emailpassword.init(
                override=emailpassword.InputOverrideConfig(
                    apis=override_email_password_apis
                )
            )
        ],
        mode="asgi",
    )
    start_st()

    with litestar_test_client as client:
        response = client.get(
            url="/auth/signup/email/exists?email=test@example.com",
        )

    dict_response = json.loads(response.text)
    assert response.status_code == 203
    assert dict_response["custom"]


def test_optional_session(litestar_test_client: TestClient[Litestar]):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[session.init(get_token_transfer_method=get_token_transfer_method)],
        mode="asgi",
    )
    start_st()

    with litestar_test_client as client:
        response = client.get(
            url="handle-session-optional",
        )

    dict_response = json.loads(response.text)
    assert response.status_code == 200
    assert dict_response["s"] == "empty session"


@mark.parametrize("token_transfer_method", ["cookie", "header"])
def test_should_clear_all_response_during_refresh_if_unauthorized(
        litestar_test_client: TestClient[Litestar], token_transfer_method: str
):
    def override_session_apis(oi: APIInterface):
        oi_refresh_post = oi.refresh_post

        async def refresh_post(
                api_options: SessionAPIOptions, user_context: Dict[str, Any]
        ):
            await oi_refresh_post(api_options, user_context)
            raise UnauthorisedError("unauthorized", clear_tokens=True)

        oi.refresh_post = refresh_post
        return oi

    init(
        **get_st_init_args(
            [
                session.init(
                    anti_csrf="VIA_TOKEN",
                    override=session.InputOverrideConfig(apis=override_session_apis),
                )
            ]
        )
    )
    start_st()

    with litestar_test_client as client:
        res = client.post("/create", headers={"st-auth-mode": token_transfer_method})
    info = extract_info(res)  # pyright: ignore

    assert info["accessTokenFromAny"] is not None
    assert info["refreshTokenFromAny"] is not None

    headers: Dict[str, Any] = {}
    cookies: Dict[str, Any] = {}

    if token_transfer_method == "header":
        headers.update({"authorization": f"Bearer {info['refreshTokenFromAny']}"})
    else:
        cookies.update(
            {"sRefreshToken": info["refreshTokenFromAny"], "sIdRefreshToken": "asdf"}
        )

    if info["antiCsrf"] is not None:
        headers.update({"anti-csrf": info["antiCsrf"]})

    with litestar_test_client as client:
        res = client.post("/auth/session/refresh", headers=headers, cookies=cookies)
    info = extract_info(res)  # pyright: ignore

    assert res.status_code == 401
    assert_info_clears_tokens(info, token_transfer_method)


@mark.parametrize("token_transfer_method", ["cookie", "header"])
def test_revoking_session_after_create_new_session_with_throwing_unauthorized_error(
        litestar_test_client: TestClient[Litestar], token_transfer_method: str
):
    init(
        **get_st_init_args(
            [
                session.init(
                    anti_csrf="VIA_TOKEN",
                )
            ]
        )
    )
    start_st()

    with litestar_test_client as client:
        res = client.post(
            "/create-throw", headers={"st-auth-mode": token_transfer_method}
        )
    info = extract_info(res)  # pyright: ignore

    assert res.status_code == 401
    assert_info_clears_tokens(info, token_transfer_method)


@mark.asyncio
async def test_search_with_email_t(litestar_test_client: TestClient[Litestar]):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            emailpassword.init(),
        ],
        mode="asgi",
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(emailpassword=True)
    query = {"limit": "10", "email": "t"}
    with litestar_test_client as client:
        res = client.get(
            "/auth/dashboard/api/users",
            headers={
                "Authorization": "Bearer testapikey",
                "Content-Type": "application/json",
            },
            params=query,
        )
    info = extract_info(res)  # pyright: ignore
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 5


@mark.asyncio
async def test_search_with_email_multiple_email_entry(
        litestar_test_client: TestClient[Litestar],
):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            emailpassword.init(),
        ],
        mode="asgi",
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(emailpassword=True)
    query = {"limit": "10", "email": "iresh;john"}
    with litestar_test_client as client:
        res = client.get(
            "/auth/dashboard/api/users",
            headers={
                "Authorization": "Bearer testapikey",
                "Content-Type": "application/json",
            },
            params=query,
        )
    info = extract_info(res)  # pyright: ignore
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 1


@mark.asyncio
async def test_search_with_email_iresh(litestar_test_client: TestClient[Litestar]):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            emailpassword.init(),
        ],
        mode="asgi",
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(emailpassword=True)
    query = {"limit": "10", "email": "iresh"}
    with litestar_test_client as client:
        res = client.get(
            "/auth/dashboard/api/users",
            headers={
                "Authorization": "Bearer testapikey",
                "Content-Type": "application/json",
            },
            params=query,
        )
    info = extract_info(res)  # pyright: ignore
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 0


@mark.asyncio
async def test_search_with_phone_plus_one(litestar_test_client: TestClient[Litestar]):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            PasswordlessRecipe.init(
                contact_config=ContactConfig(contact_method="EMAIL"),
                flow_type="USER_INPUT_CODE",
            ),
        ],
        mode="asgi",
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(passwordless=True)
    query = {"limit": "10", "phone": "+1"}
    with litestar_test_client as client:
        res = client.get(
            "/auth/dashboard/api/users",
            headers={
                "Authorization": "Bearer testapikey",
                "Content-Type": "application/json",
            },
            params=query,
        )
    info = extract_info(res)  # pyright: ignore
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 3


@mark.asyncio
async def test_search_with_phone_one_bracket(
        litestar_test_client: TestClient[Litestar],
):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            PasswordlessRecipe.init(
                contact_config=ContactConfig(contact_method="EMAIL"),
                flow_type="USER_INPUT_CODE",
            ),
        ],
        mode="asgi",
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(passwordless=True)
    query = {"limit": "10", "phone": "1("}
    with litestar_test_client as client:
        res = client.get(
            "/auth/dashboard/api/users",
            headers={
                "Authorization": "Bearer testapikey",
                "Content-Type": "application/json",
            },
            params=query,
        )
    info = extract_info(res)  # pyright: ignore
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 0


@mark.asyncio
async def test_search_with_provider_google(litestar_test_client: TestClient[Litestar]):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[
                        thirdparty.Apple(
                            client_id="4398792-io.supertokens.example.service",
                            client_key_id="7M48Y4RYDL",
                            client_team_id="YWQCXGJRJL",
                            client_private_key="-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                        ),
                        thirdparty.Google(
                            client_id="467101b197249757c71f",
                            client_secret="e97051221f4b6426e8fe8d51486396703012f5bd",
                        ),
                        thirdparty.Github(
                            client_id="1060725074195-kmeum4crr01uirfl2op9kd5acmi9jutn.apps.googleusercontent.com",
                            client_secret="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",
                        ),
                    ]
                )
            ),
        ],
        mode="asgi",
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(thirdparty=True)
    query = {"limit": "10", "provider": "google"}
    with litestar_test_client as client:
        res = client.get(
            "/auth/dashboard/api/users",
            headers={
                "Authorization": "Bearer testapikey",
                "Content-Type": "application/json",
            },
            params=query,
        )
    info = extract_info(res)  # pyright: ignore
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 3


@mark.asyncio
async def test_search_with_provider_google_and_phone_1(
        litestar_test_client: TestClient[Litestar],
):
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="litestar",
        recipe_list=[
            session.init(
                anti_csrf="VIA_TOKEN",
                cookie_domain="supertokens.io",
                get_token_transfer_method=get_token_transfer_method,
            ),
            DashboardRecipe.init(
                api_key="testapikey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
            PasswordlessRecipe.init(
                contact_config=ContactConfig(contact_method="EMAIL"),
                flow_type="USER_INPUT_CODE",
            ),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[
                        thirdparty.Apple(
                            client_id="4398792-io.supertokens.example.service",
                            client_key_id="7M48Y4RYDL",
                            client_team_id="YWQCXGJRJL",
                            client_private_key="-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                        ),
                        thirdparty.Google(
                            client_id="467101b197249757c71f",
                            client_secret="e97051221f4b6426e8fe8d51486396703012f5bd",
                        ),
                        thirdparty.Github(
                            client_id="1060725074195-kmeum4crr01uirfl2op9kd5acmi9jutn.apps.googleusercontent.com",
                            client_secret="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",
                        ),
                    ]
                )
            ),
        ],
        mode="asgi",
    )
    start_st()
    querier = Querier.get_instance(DashboardRecipe.recipe_id)
    cdi_version = await querier.get_api_version()
    if not cdi_version:
        skip()
    if not is_version_gte(cdi_version, "2.20"):
        skip()
    await create_users(thirdparty=True, passwordless=True)
    query = {"limit": "10", "provider": "google", "phone": "1"}
    with litestar_test_client as client:
        res = client.get(
            "/auth/dashboard/api/users",
            headers={
                "Authorization": "Bearer testapikey",
                "Content-Type": "application/json",
            },
            params=query,
        )
    info = extract_info(res)  # pyright: ignore
    assert res.status_code == 200
    assert len(info["body"]["users"]) == 0
