from typing import Optional

from fastapi import FastAPI
from pytest import fixture, mark
from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe import dashboard, emailpassword, session
from supertokens_python.recipe.dashboard.utils import (
    DashboardConfig,
    validate_and_normalise_user_input,
)

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

API_KEY = "someKey"
DASHBOARD_USER_EMAIL = "dashboard-user@example.com"
DASHBOARD_USER_PASSWORD = "dashboardPassword123"


@fixture(scope="function")
def app():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


def init_st_with_dashboard(api_key: Optional[str]):
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(),
                emailpassword.init(),
                dashboard.init(api_key=api_key),
            ],
        )
    )


def get_user_count(app: TestClient, authorization: str):
    return app.get(
        "/auth/dashboard/api/users/count",
        headers={"authorization": authorization},
    )


async def sign_in_to_dashboard(app: TestClient) -> str:
    await Querier.get_instance().send_post_request(
        NormalisedURLPath("/recipe/dashboard/user"),
        {"email": DASHBOARD_USER_EMAIL, "password": DASHBOARD_USER_PASSWORD},
        user_context={},
    )
    res = app.post(
        "/auth/dashboard/api/signin",
        json={"email": DASHBOARD_USER_EMAIL, "password": DASHBOARD_USER_PASSWORD},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "OK"
    return res.json()["sessionId"]


@mark.parametrize("api_key", ["", " ", "\t"])
async def test_blank_api_key_is_normalised_to_session_mode(api_key: str):
    config = validate_and_normalise_user_input(DashboardConfig(api_key=api_key))

    assert config.api_key is None
    assert config.auth_mode == "email-password"


@mark.parametrize("api_key", ["", " "])
async def test_blank_api_key_does_not_accept_an_empty_bearer_token(
    app: TestClient, api_key: str
):
    init_st_with_dashboard(api_key)

    res = get_user_count(app, "Bearer  x")

    assert res.status_code == 401


async def test_blank_api_key_rejects_key_validation(app: TestClient):
    init_st_with_dashboard("")

    res = app.post(
        "/auth/dashboard/api/key/validate",
        headers={"authorization": "Bearer  x"},
    )

    assert res.status_code == 401


@mark.parametrize("api_key", ["", " "])
async def test_blank_api_key_uses_dashboard_sessions(app: TestClient, api_key: str):
    init_st_with_dashboard(api_key)
    session_id = await sign_in_to_dashboard(app)

    res = get_user_count(app, f"Bearer {session_id}")

    assert res.status_code == 200
    assert res.json()["status"] == "OK"


async def test_api_key_grants_access(app: TestClient):
    init_st_with_dashboard(API_KEY)

    res = get_user_count(app, f"Bearer {API_KEY}")

    assert res.status_code == 200
    assert res.json()["status"] == "OK"

    res = app.post(
        "/auth/dashboard/api/key/validate",
        headers={"authorization": f"Bearer {API_KEY}"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "OK"


@mark.parametrize(
    "authorization",
    [
        "Bearer wrongKey",
        f"Bearer {API_KEY}x",
        "Bearer  x",
        "Bearer  ",
        "Bearer",
        API_KEY,
        f"Basic {API_KEY}",
    ],
)
async def test_api_key_rejects_wrong_keys(app: TestClient, authorization: str):
    init_st_with_dashboard(API_KEY)

    res = get_user_count(app, authorization)

    assert res.status_code == 401
