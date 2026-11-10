from typing import Any, Awaitable, Callable, Dict, List, Optional, Union
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
    passwordless,
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
from supertokens_python.recipe.passwordless.api import (
    implementation as passwordless_api,
)
from supertokens_python.recipe.passwordless.asyncio import signinup
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
)
from supertokens_python.recipe.thirdparty.asyncio import manually_create_or_update_user
from supertokens_python.recipe.thirdparty.interfaces import (
    ManuallyCreateOrUpdateUserOkResult,
)
from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo
from supertokens_python.types import LoginMethod, RecipeUserId, User
from supertokens_python.types.base import AccountInfoInput

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

EMAIL = "x@example.com"


@fixture(scope="function")
def app():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


class NoopPasswordlessEmailService(
    passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
):
    async def send_email(
        self,
        template_vars: passwordless.EmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        pass


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
                passwordless.init(
                    flow_type="USER_INPUT_CODE",
                    contact_config=passwordless.ContactEmailOnlyConfig(),
                    email_delivery=passwordless.EmailDeliveryConfig(
                        NoopPasswordlessEmailService()
                    ),
                ),
                thirdparty.init(),
                multitenancy.init(),
                session.init(),
            ],
        )
    )

    for tenant_id in ["t1", "t2"]:
        await create_or_update_tenant(
            tenant_id,
            TenantConfigCreateOrUpdate(
                first_factors=["emailpassword", "thirdparty", "otp-email"]
            ),
        )


async def create_emailpassword_login_method_on_t1() -> RecipeUserId:
    ep_resp = await sign_up("t1", EMAIL, "password1")
    assert isinstance(ep_resp, SignUpOkResult)
    return ep_resp.recipe_user_id


async def create_passwordless_login_method_on_t1() -> RecipeUserId:
    pl_resp = await signinup("t1", EMAIL, None)
    return pl_resp.recipe_user_id


async def create_primary_user_on_t1_shared_with_t2(
    create_login_method_on_t1: Callable[
        [], Awaitable[RecipeUserId]
    ] = create_emailpassword_login_method_on_t1,
) -> User:
    """A primary user whose emailpassword (or passwordless) login method only exists on t1,
    linked to a third party login method that is shared with t2, so the core lists the
    primary user for t2 as well."""
    primary_resp = await create_primary_user(await create_login_method_on_t1())
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


def passwordless_primary_user_on_t1_shared_with_t2() -> User:
    # The passwordless login method is only on t1, but the linked third party login method with
    # the same email is also on t2, so the core lists the primary user for t2.
    pl = LoginMethod("passwordless", "pl-1", ["t1"], EMAIL, None, None, None, 0, True)
    tp = LoginMethod(
        "thirdparty",
        "tp-1",
        ["t1", "t2"],
        EMAIL,
        None,
        ThirdPartyInfo("tp-user", "google"),
        None,
        0,
        True,
    )
    return User("pl-1", True, ["t1", "t2"], [EMAIL], [], [], MagicMock(), [pl, tp], 0)


def core_listing(users: List[User]) -> MagicMock:
    account_linking = MagicMock()
    account_linking.get_instance.return_value.recipe_implementation.list_users_by_account_info = AsyncMock(
        return_value=users
    )
    return account_linking


async def passwordless_lookups_on_t2(users: List[User]):
    account_linking = core_listing(users)
    with patch.object(auth_utils, "AccountLinkingRecipe", account_linking):
        with patch.object(passwordless_api, "AccountLinkingRecipe", account_linking):
            create_code_user = (
                await passwordless_api.get_passwordless_user_by_account_info(
                    "t2", {}, AccountInfoInput(email=EMAIL)
                )
            )
            consume_code_user = await auth_utils.get_authenticating_user_and_add_to_current_tenant_if_required(
                recipe_id="passwordless",
                email=EMAIL,
                phone_number=None,
                third_party=None,
                tenant_id="t2",
                session=None,
                check_credentials_on_tenant=AsyncMock(return_value=True),
                user_context={},
            )
    return create_code_user, consume_code_user


async def test_passwordless_create_code_ignores_a_login_method_from_another_tenant():
    create_code_user, consume_code_user = await passwordless_lookups_on_t2(
        [passwordless_primary_user_on_t1_shared_with_t2()]
    )

    # create_code and consume_code must agree that this is a sign up on t2
    assert create_code_user is None
    assert consume_code_user is None


async def test_passwordless_create_code_finds_the_user_of_the_current_tenant():
    t2_user = User(
        "pl-2",
        False,
        ["t2"],
        [EMAIL],
        [],
        [],
        MagicMock(),
        [LoginMethod("passwordless", "pl-2", ["t2"], EMAIL, None, None, None, 0, True)],
        0,
    )

    create_code_user, consume_code_user = await passwordless_lookups_on_t2(
        [passwordless_primary_user_on_t1_shared_with_t2(), t2_user]
    )

    assert create_code_user is not None
    assert create_code_user.user.id == "pl-2"
    assert consume_code_user is not None
    assert consume_code_user.user.id == "pl-2"


async def test_passwordless_create_code_with_a_session_recognises_the_session_users_login_method(
    app: TestClient,
):
    # The session user's passwordless login method is only on t1. createCode on t2 must still
    # treat it as the session user's own login method, as consumeCode does, instead of trying
    # to link a new user (which fails, because automatic account linking is off).
    await init_st()
    primary_user = await create_primary_user_on_t1_shared_with_t2(
        create_passwordless_login_method_on_t1
    )
    access_token = await session_for_primary_user_on_t2(primary_user)

    res = app.post(
        url="/auth/t2/signinup/code",
        json={"email": EMAIL, "shouldTryLinkingWithSessionUser": True},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert res.status_code == 200
    assert res.json()["status"] == "OK"


PHONE = "+14155552671"


def primary_user_with_passwordless_email_and_phone_on_t1() -> User:
    # The passwordless login method (email and phone) is only on t1, and the linked third party
    # login method with the same email is also on t2, so the core lists the primary user for t2.
    pl = LoginMethod("passwordless", "pl-1", ["t1"], EMAIL, PHONE, None, None, 0, True)
    tp = LoginMethod(
        "thirdparty",
        "tp-1",
        ["t1", "t2"],
        EMAIL,
        None,
        ThirdPartyInfo("tp-user", "google"),
        None,
        0,
        True,
    )
    return User(
        "pl-1", True, ["t1", "t2"], [EMAIL], [PHONE], [], MagicMock(), [pl, tp], 0
    )


async def consume_code_on_t2_with_association_conflict(status_error: Any):
    primary = primary_user_with_passwordless_email_and_phone_on_t1()
    account_linking = core_listing([primary])
    list_users = account_linking.get_instance.return_value.recipe_implementation.list_users_by_account_info
    session = MagicMock()
    session.get_user_id.return_value = primary.id
    associate = AsyncMock(return_value=status_error)

    with patch.object(auth_utils, "AccountLinkingRecipe", account_linking):
        with patch.object(auth_utils, "get_user", AsyncMock(return_value=primary)):
            with patch.object(auth_utils, "associate_user_to_tenant", associate):
                result = await auth_utils.get_authenticating_user_and_add_to_current_tenant_if_required(
                    recipe_id="passwordless",
                    email=EMAIL,
                    phone_number=None,
                    third_party=None,
                    tenant_id="t2",
                    session=session,
                    check_credentials_on_tenant=AsyncMock(return_value=True),
                    user_context={},
                )
    return result, list_users.await_count, associate.await_count


async def test_session_fallback_skips_a_login_method_whose_phone_number_is_taken_on_the_tenant():
    from supertokens_python.recipe.multitenancy.interfaces import (
        AssociateUserToTenantPhoneNumberAlreadyExistsError,
    )

    (
        result,
        list_calls,
        associate_calls,
    ) = await consume_code_on_t2_with_association_conflict(
        AssociateUserToTenantPhoneNumberAlreadyExistsError()
    )

    # The users are listed by email, so listing again cannot find the user holding the phone
    # number. The attempt is handled as a sign up instead of retrying until it fails.
    assert result is None
    assert list_calls == 1
    assert associate_calls == 1


async def test_session_fallback_retries_an_email_conflict_only_once():
    from supertokens_python.recipe.multitenancy.interfaces import (
        AssociateUserToTenantEmailAlreadyExistsError,
    )

    (
        result,
        list_calls,
        associate_calls,
    ) = await consume_code_on_t2_with_association_conflict(
        AssociateUserToTenantEmailAlreadyExistsError()
    )

    assert result is None
    assert list_calls == 2
    assert associate_calls == 2


async def test_passwordless_create_code_with_a_session_ignores_a_login_method_whose_phone_number_is_taken_on_the_tenant():
    primary = primary_user_with_passwordless_email_and_phone_on_t1()
    t2_user = User(
        "pl-2",
        False,
        ["t2"],
        [],
        [PHONE],
        [],
        MagicMock(),
        [LoginMethod("passwordless", "pl-2", ["t2"], None, PHONE, None, None, 0, True)],
        0,
    )
    account_linking = MagicMock()

    async def list_users_by_account_info(**kwargs: Any) -> List[User]:
        if kwargs["account_info"].phone_number == PHONE:
            return [t2_user]
        return [primary]

    account_linking.get_instance.return_value.recipe_implementation.list_users_by_account_info = list_users_by_account_info
    session = MagicMock()
    session.get_user_id.return_value = primary.id

    with patch.object(passwordless_api, "AccountLinkingRecipe", account_linking):
        with patch.object(
            passwordless_api, "get_user", AsyncMock(return_value=primary)
        ):
            create_code_user = (
                await passwordless_api.get_passwordless_user_by_account_info(
                    "t2", {}, AccountInfoInput(email=EMAIL), session
                )
            )

    # consume_code cannot add the login method to t2, so create_code must not treat it as a sign in
    assert create_code_user is None
