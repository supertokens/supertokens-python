from typing import Any, Dict, List, Optional, Union
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from pytest import fixture, mark
from supertokens_python import auth_utils, init
from supertokens_python.asyncio import get_user
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
from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
)
from supertokens_python.recipe.thirdparty.asyncio import manually_create_or_update_user
from supertokens_python.recipe.thirdparty.interfaces import (
    ManuallyCreateOrUpdateUserOkResult,
)
from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo
from supertokens_python.types import LoginMethod, User

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


class SignInResult:
    def __init__(self, status: str, user_id: Optional[str]):
        self.status = status
        self.user_id = user_id


def sign_in(
    app: TestClient, tenant_id: str, password: str, access_token: Optional[str] = None
) -> SignInResult:
    form_fields = [
        {"id": "email", "value": EMAIL},
        {"id": "password", "value": password},
    ]
    if access_token is None:
        res = app.post(
            url=f"/auth/{tenant_id}/signin", json={"formFields": form_fields}
        )
    else:
        res = app.post(
            url=f"/auth/{tenant_id}/signin",
            json={"formFields": form_fields, "shouldTryLinkingWithSessionUser": True},
            headers={"Authorization": f"Bearer {access_token}"},
        )
    assert res.status_code == 200
    body = res.json()
    user = body.get("user")
    return SignInResult(body["status"], None if user is None else user["id"])


async def session_for_primary_user_on_t2(primary_user: User) -> str:
    user = await get_user(primary_user.id)
    assert user is not None
    tp_login_method = next(
        lm for lm in user.login_methods if lm.recipe_id == "thirdparty"
    )
    s = await create_new_session_without_request_response(
        "t2", tp_login_method.recipe_user_id
    )
    return s.get_access_token()


async def emailpassword_tenant_ids(primary_user_id: str) -> List[str]:
    user = await get_user(primary_user_id)
    assert user is not None
    return sorted(
        next(
            lm for lm in user.login_methods if lm.recipe_id == "emailpassword"
        ).tenant_ids
    )


async def test_sign_in_ignores_a_linked_login_method_from_another_tenant(
    app: TestClient,
):
    await init_st()
    primary_user = await create_primary_user_on_t1_shared_with_t2()

    t2_sign_up = await sign_up("t2", EMAIL, "password2")
    assert isinstance(t2_sign_up, SignUpOkResult)
    assert t2_sign_up.user.id != primary_user.id

    result = sign_in(app, "t2", "password2")

    assert result.status == "OK"
    assert result.user_id == t2_sign_up.user.id


async def test_sign_in_does_not_accept_the_password_of_a_linked_login_method_from_another_tenant(
    app: TestClient,
):
    await init_st()
    await create_primary_user_on_t1_shared_with_t2()

    t2_sign_up = await sign_up("t2", EMAIL, "password2")
    assert isinstance(t2_sign_up, SignUpOkResult)

    result = sign_in(app, "t2", "password1")

    assert result.status == "WRONG_CREDENTIALS_ERROR"


async def test_sign_in_with_a_session_adds_the_session_users_login_method_to_the_tenant(
    app: TestClient,
):
    await init_st()
    primary_user = await create_primary_user_on_t1_shared_with_t2()
    access_token = await session_for_primary_user_on_t2(primary_user)

    result = sign_in(app, "t2", "password1", access_token)

    assert result.status == "OK"
    assert result.user_id == primary_user.id
    assert await emailpassword_tenant_ids(primary_user.id) == ["t1", "t2"]


async def test_sign_in_with_a_session_and_a_wrong_password_does_not_add_the_login_method(
    app: TestClient,
):
    await init_st()
    primary_user = await create_primary_user_on_t1_shared_with_t2()
    access_token = await session_for_primary_user_on_t2(primary_user)

    result = sign_in(app, "t2", "wrong-password", access_token)

    assert result.status == "WRONG_CREDENTIALS_ERROR"
    assert await emailpassword_tenant_ids(primary_user.id) == ["t1"]


async def test_session_fallback_skips_a_login_method_that_is_on_no_tenant():
    # The emailpassword login method was removed from every tenant, and the third party login
    # method with the same email is on t2, so the core lists the primary user for t2.
    ep = LoginMethod("emailpassword", "ep-1", [], EMAIL, None, None, None, 0, True)
    tp = LoginMethod(
        "thirdparty",
        "tp-1",
        ["t2"],
        EMAIL,
        None,
        ThirdPartyInfo("tp-user", "google"),
        None,
        0,
        True,
    )
    primary = User("ep-1", True, ["t2"], [EMAIL], [], [], MagicMock(), [ep, tp], 0)
    account_linking = MagicMock()
    account_linking.get_instance.return_value.recipe_implementation.list_users_by_account_info = AsyncMock(
        return_value=[primary]
    )
    session = MagicMock()
    session.get_user_id.return_value = primary.id
    check_credentials_on_tenant = AsyncMock(return_value=True)

    with patch.object(auth_utils, "AccountLinkingRecipe", account_linking):
        with patch.object(auth_utils, "get_user", AsyncMock(return_value=primary)):
            result = await auth_utils.get_authenticating_user_and_add_to_current_tenant_if_required(
                recipe_id="emailpassword",
                email=EMAIL,
                phone_number=None,
                third_party=None,
                tenant_id="t2",
                session=session,
                check_credentials_on_tenant=check_credentials_on_tenant,
                user_context={},
            )

    assert result is None
    check_credentials_on_tenant.assert_not_called()
