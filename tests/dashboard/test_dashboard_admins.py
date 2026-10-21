from typing import List, Optional, Tuple

from fastapi import FastAPI
from pytest import fixture, mark
from supertokens_python import init
from supertokens_python.asyncio import get_user
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe import (
    accountlinking,
    dashboard,
    emailpassword,
    session,
    thirdparty,
)
from supertokens_python.recipe.accountlinking.asyncio import (
    create_primary_user,
    link_accounts,
)
from supertokens_python.recipe.accountlinking.interfaces import (
    CreatePrimaryUserOkResult,
    LinkAccountsOkResult,
)
from supertokens_python.recipe.emailpassword.asyncio import sign_in, sign_up
from supertokens_python.recipe.emailpassword.interfaces import (
    SignInOkResult,
    SignUpOkResult,
)
from supertokens_python.recipe.thirdparty.asyncio import manually_create_or_update_user
from supertokens_python.recipe.thirdparty.interfaces import (
    ManuallyCreateOrUpdateUserOkResult,
)
from supertokens_python.types import RecipeUserId

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

DASHBOARD_USER_EMAIL = "dashboard-user@example.com"
DASHBOARD_USER_PASSWORD = "dashboardPassword123"
ORIGINAL_PASSWORD = "originalPassword123"
NEW_PASSWORD = "newPassword123"


@fixture(scope="function")
def app():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


async def init_st_with_dashboard_session(
    app: TestClient,
    admins: Optional[List[str]],
    with_account_linking: bool = False,
) -> str:
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(),
                emailpassword.init(),
                dashboard.init(admins=admins),
                *(
                    [thirdparty.init(), accountlinking.init()]
                    if with_account_linking
                    else []
                ),
            ],
        )
    )

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


async def create_user() -> str:
    res = await sign_up("public", "user@example.com", ORIGINAL_PASSWORD)
    assert isinstance(res, SignUpOkResult)
    return res.user.id


def update_password(app: TestClient, session_id: str, user_id: str, query: str = ""):
    return app.put(
        f"/auth/dashboard/api/user/password{query}",
        headers={"authorization": f"Bearer {session_id}"},
        json={"recipeUserId": user_id, "newPassword": NEW_PASSWORD},
    )


async def assert_password_unchanged():
    res = await sign_in("public", "user@example.com", ORIGINAL_PASSWORD)
    assert isinstance(res, SignInOkResult)


async def assert_password_changed():
    res = await sign_in("public", "user@example.com", NEW_PASSWORD)
    assert isinstance(res, SignInOkResult)


@mark.parametrize("admins", [["someone-else@example.com"], []])
@mark.parametrize("query", ["?x=/api/signout", "?x=/api/analytics"])
async def test_write_exemptions_ignore_the_query_string(
    app: TestClient, admins: List[str], query: str
):
    session_id = await init_st_with_dashboard_session(app, admins)
    user_id = await create_user()

    res = update_password(app, session_id, user_id, query)

    assert res.status_code == 403
    await assert_password_unchanged()


@mark.parametrize("admins", [["someone-else@example.com"], []])
async def test_non_admins_cannot_write(app: TestClient, admins: List[str]):
    session_id = await init_st_with_dashboard_session(app, admins)
    user_id = await create_user()

    res = update_password(app, session_id, user_id)

    assert res.status_code == 403
    await assert_password_unchanged()


@mark.parametrize("admins", [["someone-else@example.com"], []])
async def test_non_admins_can_post_analytics(app: TestClient, admins: List[str]):
    session_id = await init_st_with_dashboard_session(app, admins)

    res = app.post(
        "/auth/dashboard/api/analytics",
        headers={"authorization": f"Bearer {session_id}"},
        json={"email": DASHBOARD_USER_EMAIL, "dashboardVersion": "0.0.0"},
    )

    assert res.status_code == 200


@mark.parametrize("admins", [["someone-else@example.com"], []])
async def test_non_admins_can_sign_out(app: TestClient, admins: List[str]):
    session_id = await init_st_with_dashboard_session(app, admins)

    res = app.post(
        "/auth/dashboard/api/signout",
        headers={"authorization": f"Bearer {session_id}"},
    )

    assert res.status_code == 200
    assert res.json()["status"] == "OK"


@mark.parametrize("admins", [[DASHBOARD_USER_EMAIL], None])
async def test_admins_can_write(app: TestClient, admins: Optional[List[str]]):
    session_id = await init_st_with_dashboard_session(app, admins)
    user_id = await create_user()

    res = update_password(app, session_id, user_id)

    assert res.status_code == 200
    assert res.json()["status"] == "OK"
    await assert_password_changed()


async def create_linked_user() -> Tuple[str, str]:
    user_id = await create_user()
    primary_res = await create_primary_user(RecipeUserId(user_id))
    assert isinstance(primary_res, CreatePrimaryUserOkResult)
    tp_res = await manually_create_or_update_user(
        "public", "google", "tp-user", "user@example.com", False
    )
    assert isinstance(tp_res, ManuallyCreateOrUpdateUserOkResult)
    link_res = await link_accounts(tp_res.recipe_user_id, primary_res.user.id)
    assert isinstance(link_res, LinkAccountsOkResult)
    assert await get_login_method_count(primary_res.user.id) == 2
    return primary_res.user.id, tp_res.recipe_user_id.get_as_string()


async def get_login_method_count(user_id: str) -> int:
    user = await get_user(user_id)
    assert user is not None
    return len(user.login_methods)


def unlink_user(app: TestClient, session_id: str, recipe_user_id: str):
    return app.get(
        f"/auth/dashboard/api/user/unlink?recipeUserId={recipe_user_id}",
        headers={"authorization": f"Bearer {session_id}"},
    )


@mark.parametrize("admins", [["someone-else@example.com"], []])
async def test_non_admins_cannot_unlink(app: TestClient, admins: List[str]):
    session_id = await init_st_with_dashboard_session(
        app, admins, with_account_linking=True
    )
    primary_user_id, linked_recipe_user_id = await create_linked_user()

    res = unlink_user(app, session_id, linked_recipe_user_id)

    assert res.status_code == 403
    assert await get_login_method_count(primary_user_id) == 2


@mark.parametrize("admins", [[DASHBOARD_USER_EMAIL], None])
async def test_admins_can_unlink(app: TestClient, admins: Optional[List[str]]):
    session_id = await init_st_with_dashboard_session(
        app, admins, with_account_linking=True
    )
    primary_user_id, linked_recipe_user_id = await create_linked_user()

    res = unlink_user(app, session_id, linked_recipe_user_id)

    assert res.status_code == 200
    assert res.json()["status"] == "OK"
    assert await get_login_method_count(primary_user_id) == 1


@mark.parametrize("admins", [["someone-else@example.com"], []])
async def test_non_admins_can_read_user_details(app: TestClient, admins: List[str]):
    session_id = await init_st_with_dashboard_session(app, admins)
    user_id = await create_user()

    res = app.get(
        f"/auth/dashboard/api/user?userId={user_id}&recipeId=emailpassword",
        headers={"authorization": f"Bearer {session_id}"},
    )

    assert res.status_code == 200
    assert res.json()["status"] == "OK"
