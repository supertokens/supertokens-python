from typing import Any, Dict, Optional, Union

from fastapi import FastAPI
from pytest import fixture, mark
from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import (
    accountlinking,
    emailpassword,
    multitenancy,
    session,
    thirdparty,
)
from supertokens_python.recipe.accountlinking import (
    ShouldAutomaticallyLink,
    ShouldNotAutomaticallyLink,
)
from supertokens_python.recipe.accountlinking.asyncio import (
    create_primary_user,
    link_accounts,
)
from supertokens_python.recipe.accountlinking.types import (
    AccountInfoWithRecipeIdAndUserId,
)
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.recipe.multitenancy.asyncio import (
    associate_user_to_tenant,
    create_or_update_tenant,
)
from supertokens_python.recipe.multitenancy.interfaces import (
    AssociateUserToTenantOkResult,
    TenantConfigCreateOrUpdate,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.thirdparty.asyncio import manually_create_or_update_user
from supertokens_python.recipe.thirdparty.interfaces import (
    ManuallyCreateOrUpdateUserOkResult,
)
from supertokens_python.types import User

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

EMAIL = "x@example.com"


@fixture(scope="function")
def app():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


async def init_st():
    async def should_do_automatic_account_linking(
        _new_account_info: AccountInfoWithRecipeIdAndUserId,
        _user: Optional[User],
        _session: Optional[SessionContainer],
        _tenant_id: str,
        _user_context: Dict[str, Any],
    ) -> Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink]:
        return ShouldNotAutomaticallyLink()

    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                accountlinking.init(
                    should_do_automatic_account_linking=should_do_automatic_account_linking
                ),
                emailpassword.init(),
                thirdparty.init(),
                multitenancy.init(),
                session.init(),
            ],
        )
    )

    for tenant_id in ["t1", "t2"]:
        await create_or_update_tenant(
            tenant_id,
            TenantConfigCreateOrUpdate(first_factors=["emailpassword", "thirdparty"]),
        )


async def create_primary_user_on_t1_shared_with_t2() -> User:
    """A primary user whose emailpassword login method only exists on t1, linked to a
    third party login method that is shared with t2, so the core lists the primary user
    for t2 as well."""
    ep_resp = await sign_up("t1", EMAIL, "password1")
    assert isinstance(ep_resp, SignUpOkResult)
    primary_resp = await create_primary_user(ep_resp.recipe_user_id)
    assert primary_resp.status == "OK"

    tp_resp = await manually_create_or_update_user(
        "t1", "google", "tp-user", EMAIL, False
    )
    assert isinstance(tp_resp, ManuallyCreateOrUpdateUserOkResult)
    link_resp = await link_accounts(tp_resp.recipe_user_id, primary_resp.user.id)
    assert link_resp.status == "OK"
    associate_resp = await associate_user_to_tenant("t2", tp_resp.recipe_user_id)
    assert isinstance(associate_resp, AssociateUserToTenantOkResult)

    return primary_resp.user


def sign_in(app: TestClient, tenant_id: str, password: str) -> Dict[str, Any]:
    res = app.post(
        url=f"/auth/{tenant_id}/signin",
        json={
            "formFields": [
                {"id": "email", "value": EMAIL},
                {"id": "password", "value": password},
            ]
        },
    )
    assert res.status_code == 200
    return res.json()


async def test_sign_in_ignores_a_linked_login_method_from_another_tenant(
    app: TestClient,
):
    await init_st()
    primary_user = await create_primary_user_on_t1_shared_with_t2()

    t2_sign_up = await sign_up("t2", EMAIL, "password2")
    assert isinstance(t2_sign_up, SignUpOkResult)
    assert t2_sign_up.user.id != primary_user.id

    body = sign_in(app, "t2", "password2")

    assert body["status"] == "OK"
    assert body["user"]["id"] == t2_sign_up.user.id


async def test_sign_in_does_not_accept_the_password_of_a_linked_login_method_from_another_tenant(
    app: TestClient,
):
    await init_st()
    await create_primary_user_on_t1_shared_with_t2()

    t2_sign_up = await sign_up("t2", EMAIL, "password2")
    assert isinstance(t2_sign_up, SignUpOkResult)

    body = sign_in(app, "t2", "password1")

    assert body["status"] == "WRONG_CREDENTIALS_ERROR"
