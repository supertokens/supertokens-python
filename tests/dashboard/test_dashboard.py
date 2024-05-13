from typing import Any, Dict, List

from fastapi import FastAPI
from pytest import fixture, mark
from tests.testclient import TestClientWithNoCookieJar as TestClient
from supertokens_python import init
from supertokens_python.constants import DASHBOARD_VERSION
from supertokens_python.framework import BaseRequest
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import (
    dashboard,
    emailpassword,
    session,
    usermetadata,
    thirdparty,
    passwordless,
)
from supertokens_python.recipe.thirdparty.asyncio import manually_create_or_update_user
from supertokens_python.recipe.dashboard import InputOverrideConfig
from supertokens_python.recipe.dashboard.interfaces import (
    RecipeInterface as DashboardRI,
)
from supertokens_python.recipe.dashboard.utils import DashboardConfig
from supertokens_python.recipe.passwordless import ContactEmailOrPhoneConfig
from supertokens_python.recipe.usermetadata.asyncio import update_user_metadata
from tests.utils import (
    clean_st,
    get_st_init_args,
    min_api_version,
    reset,
    setup_st,
    sign_up_request,
    start_st,
)


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


pytestmark = mark.asyncio


@fixture(scope="function")
async def app():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


async def test_dashboard_recipe(app: TestClient):
    def override_dashboard_functions(oi: DashboardRI) -> DashboardRI:
        async def should_allow_access(
            _request: BaseRequest,
            _config: DashboardConfig,
            _user_context: Dict[str, Any],
        ) -> bool:
            return True

        oi.should_allow_access = should_allow_access
        return oi

    st_args = get_st_init_args(
        [
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
            dashboard.init(
                api_key="someKey",
                override=InputOverrideConfig(functions=override_dashboard_functions),
            ),
        ]
    )
    init(**st_args)
    start_st()

    expected_url = (
        f"https://cdn.jsdelivr.net/gh/supertokens/dashboard@v{DASHBOARD_VERSION}/build/"
    )

    res = app.get(url="/auth/dashboard")
    assert res.status_code == 200
    assert expected_url in str(res.text)


@min_api_version("2.13")
async def test_dashboard_users_get(app: TestClient):
    def override_dashboard_functions(oi: DashboardRI) -> DashboardRI:
        async def should_allow_access(
            _request: BaseRequest,
            _config: DashboardConfig,
            _user_context: Dict[str, Any],
        ) -> bool:
            return True

        oi.should_allow_access = should_allow_access
        return oi

    st_args = get_st_init_args(
        [
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
            emailpassword.init(),
            usermetadata.init(),
            dashboard.init(
                api_key="someKey",
                override=InputOverrideConfig(
                    functions=override_dashboard_functions,
                ),
            ),
        ]
    )
    init(**st_args)
    start_st()

    user_ids: List[str] = []

    # Create two emailpassword users:
    for i in range(2):
        res = sign_up_request(app, f"user{i}@example.com", "password123")
        user_id: str = res.json()["user"]["id"]
        user_ids.append(user_id)
        assert res.status_code == 200

    await update_user_metadata(user_ids[0], {"first_name": "User1", "last_name": "Foo"})
    await update_user_metadata(user_ids[1], {"first_name": "User2"})

    res = app.get(url="/auth/dashboard/api/users?limit=5")
    body = res.json()
    assert res.status_code == 200
    assert body["users"][0]["user"]["firstName"] == "User2"
    assert body["users"][1]["user"]["lastName"] == "Foo"
    assert body["users"][1]["user"]["firstName"] == "User1"


async def test_connection_uri_has_http_prefix_if_localhost(app: TestClient):
    connection_uri = start_st()
    connection_uri_without_protocol = connection_uri.replace("http://", "")

    st_args = get_st_init_args(
        [
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
            dashboard.init(api_key="someKey"),
        ]
    )

    st_config = st_args.get("supertokens_config")
    if st_config:
        st_config.connection_uri = connection_uri_without_protocol

    init(**st_args)

    res = app.get(url="/auth/dashboard")
    assert res.status_code == 200
    assert f'window.connectionURI = "{connection_uri}"' in str(res.text)
    if st_config:
        st_config.connection_uri = "http://localhost:3567"


async def test_connection_uri_has_https_prefix_if_not_localhost(app: TestClient):
    start_st()
    connection_uri = "https://try.supertokens.com/appid-public"
    connection_uri_without_protocol = connection_uri.replace("https://", "")

    st_args = get_st_init_args(
        [
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
            dashboard.init(api_key="someKey"),
        ]
    )

    st_config = st_args.get("supertokens_config")
    if st_config:
        st_config.connection_uri = connection_uri_without_protocol

    init(**st_args)

    res = app.get(url="/auth/dashboard")
    assert res.status_code == 200
    assert f'window.connectionURI = "{connection_uri}"' in str(res.text)
    if st_config:
        st_config.connection_uri = "http://localhost:3567"


async def test_that_first_connection_uri_is_selected_among_multiple_uris(
    app: TestClient,
):
    start_st()
    first_connection_uri = "https://try.supertokens.com/appid-public"
    second_connection_uri = "https://test.supertokens.com/"
    multiple_connection_uris = f"{first_connection_uri};{second_connection_uri}"

    st_args = get_st_init_args(
        [
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
            dashboard.init(api_key="someKey"),
        ]
    )

    st_config = st_args.get("supertokens_config")
    if st_config:
        st_config.connection_uri = multiple_connection_uris

    init(**st_args)

    res = app.get(url="/auth/dashboard")
    assert res.status_code == 200
    assert f'window.connectionURI = "{first_connection_uri}"' in str(res.text)
    if st_config:
        st_config.connection_uri = "http://localhost:3567"


async def test_that_get_user_works_with_combination_recipes(app: TestClient):
    def override_dashboard_functions(oi: DashboardRI) -> DashboardRI:
        async def should_allow_access(
            _request: BaseRequest,
            _config: DashboardConfig,
            _user_context: Dict[str, Any],
        ) -> bool:
            return True

        oi.should_allow_access = should_allow_access
        return oi

    st_args = get_st_init_args(
        [
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
            thirdparty.init(),
            passwordless.init(
                contact_config=ContactEmailOrPhoneConfig(),
                flow_type="USER_INPUT_CODE",
            ),
            usermetadata.init(),
            dashboard.init(
                api_key="someKey",
                override=InputOverrideConfig(
                    functions=override_dashboard_functions,
                ),
            ),
        ]
    )
    init(**st_args)
    start_st()

    pluser = await manually_create_or_update_user(
        "public", "google", "googleid", "test@example.com"
    )

    res = app.get(
        url="/auth/dashboard/api/user",
        params={
            "userId": "randomid",
            "recipeId": "thirdparty",
        },
    )
    res_json = res.json()
    assert res_json["status"] == "NO_USER_FOUND_ERROR"

    res = app.get(
        url="/auth/dashboard/api/user",
        params={
            "userId": pluser.user.user_id,
            "recipeId": "thirdparty",
        },
    )
    res_json = res.json()
    assert res_json["status"] == "OK"
    assert res_json["user"]["id"] == pluser.user.user_id
