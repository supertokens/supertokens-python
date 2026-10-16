from typing import Any, Callable, Dict, Optional, Union

from fastapi import FastAPI
from pytest import fixture, mark
from pytest_mock import MockerFixture
from supertokens_python import init
from supertokens_python.asyncio import get_user
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import (
    accountlinking,
    emailpassword,
    emailverification,
    session,
    thirdparty,
)
from supertokens_python.recipe.accountlinking import (
    ShouldAutomaticallyLink,
    ShouldNotAutomaticallyLink,
)
from supertokens_python.recipe.accountlinking.asyncio import create_primary_user
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.accountlinking.types import (
    AccountInfoWithRecipeIdAndUserId,
)
from supertokens_python.recipe.emailpassword.asyncio import (
    create_reset_password_token,
    sign_up,
)
from supertokens_python.recipe.emailpassword.interfaces import (
    CreateResetPasswordOkResult,
    SignUpOkResult,
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

ShouldRequireVerification = Union[bool, Callable[[Optional[User]], bool]]


@fixture(scope="function")
def app():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


def init_st(should_require_verification: ShouldRequireVerification):
    async def should_do_automatic_account_linking(
        _new_account_info: AccountInfoWithRecipeIdAndUserId,
        user: Optional[User],
        _session: Optional[SessionContainer],
        _tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink]:
        if user_context.get("do_not_link") is True:
            return ShouldNotAutomaticallyLink()
        return ShouldAutomaticallyLink(
            should_require_verification=(
                should_require_verification(user)
                if callable(should_require_verification)
                else should_require_verification
            )
        )

    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                accountlinking.init(
                    should_do_automatic_account_linking=should_do_automatic_account_linking
                ),
                emailpassword.init(),
                emailverification.init(mode="OPTIONAL"),
                thirdparty.init(),
                session.init(),
            ],
        )
    )


async def create_third_party_user(
    third_party_id: str,
    third_party_user_id: str,
    is_verified: bool,
    user_context: Optional[Dict[str, Any]] = None,
) -> ManuallyCreateOrUpdateUserOkResult:
    res = await manually_create_or_update_user(
        "public",
        third_party_id,
        third_party_user_id,
        EMAIL,
        is_verified,
        user_context=user_context,
    )
    assert isinstance(res, ManuallyCreateOrUpdateUserOkResult)
    return res


async def create_primary_third_party_user(is_verified: bool) -> User:
    res = await create_third_party_user(
        "google", "primary-user", is_verified, {"do_not_link": True}
    )
    primary_res = await create_primary_user(res.recipe_user_id)
    assert primary_res.status == "OK"
    user = primary_res.user  # type: ignore
    assert isinstance(user, User)
    assert user.login_methods[0].email == EMAIL
    assert user.login_methods[0].verified == is_verified
    return user


async def get_login_method_count(user_id: str) -> int:
    user = await get_user(user_id)
    assert user is not None
    return len(user.login_methods)


async def test_does_not_link_to_a_primary_user_with_the_email_unverified():
    init_st(should_require_verification=True)
    primary_user = await create_primary_third_party_user(is_verified=False)

    res = await create_third_party_user("github", "incoming", True)

    assert res.user.id != primary_user.id
    assert await get_login_method_count(primary_user.id) == 1


async def test_does_not_link_after_password_reset_to_a_primary_user_with_the_email_unverified(
    app: TestClient,
):
    init_st(should_require_verification=True)
    primary_user = await create_primary_third_party_user(is_verified=False)

    sign_up_res = await sign_up(
        "public", EMAIL, "password1234", user_context={"do_not_link": True}
    )
    assert isinstance(sign_up_res, SignUpOkResult)
    recipe_user = sign_up_res.user
    assert recipe_user.is_primary_user is False
    assert recipe_user.login_methods[0].verified is False

    token_res = await create_reset_password_token("public", recipe_user.id, EMAIL)
    assert isinstance(token_res, CreateResetPasswordOkResult)

    res = app.post(
        "/auth/user/password/reset",
        json={
            "token": token_res.token,
            "formFields": [{"id": "password", "value": "newPassword1234"}],
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "OK"

    recipe_user_after = await get_user(recipe_user.id)
    assert recipe_user_after is not None
    assert recipe_user_after.id == recipe_user.id
    assert len(recipe_user_after.login_methods) == 1
    assert recipe_user_after.login_methods[0].verified is True
    assert await get_login_method_count(primary_user.id) == 1


async def test_links_to_a_primary_user_with_the_email_verified():
    init_st(should_require_verification=True)
    primary_user = await create_primary_third_party_user(is_verified=True)

    res = await create_third_party_user("github", "incoming", True)

    assert res.user.id == primary_user.id
    assert len(res.user.login_methods) == 2


async def test_links_to_a_primary_user_with_the_email_unverified_if_verification_is_not_required():
    init_st(should_require_verification=False)
    primary_user = await create_primary_third_party_user(is_verified=False)

    res = await create_third_party_user("github", "incoming", False)

    assert res.user.id == primary_user.id
    assert len(res.user.login_methods) == 2


def require_verification_only_for_linking(user: Optional[User]) -> bool:
    # Verification isn't required when deciding whether the older user can become primary
    # (no user is passed then), but it is required when linking to it
    return user is not None


async def create_older_user(is_verified: bool) -> User:
    res = await create_third_party_user(
        "google", "older-user", is_verified, {"do_not_link": True}
    )
    assert res.user.is_primary_user is False
    assert res.user.login_methods[0].verified == is_verified
    return res.user


async def test_does_not_link_to_an_older_user_with_the_email_unverified():
    init_st(should_require_verification=require_verification_only_for_linking)
    older_user = await create_older_user(is_verified=False)

    res = await create_third_party_user("github", "incoming", True)

    assert res.user.id != older_user.id
    assert len(res.user.login_methods) == 1
    assert await get_login_method_count(older_user.id) == 1


async def test_links_to_an_older_user_with_the_email_verified():
    init_st(should_require_verification=require_verification_only_for_linking)
    older_user = await create_older_user(is_verified=True)

    res = await create_third_party_user("github", "incoming", True)

    assert res.user.id == older_user.id
    assert len(res.user.login_methods) == 2


async def test_links_to_an_older_user_with_the_email_unverified_if_verification_is_not_required():
    init_st(should_require_verification=False)
    older_user = await create_older_user(is_verified=False)

    res = await create_third_party_user("github", "incoming", False)

    assert res.user.id == older_user.id
    assert len(res.user.login_methods) == 2


def make_user(
    user_id: str, is_primary_user: bool, login_method: Dict[str, Any]
) -> User:
    login_method = {
        "recipeUserId": user_id,
        "tenantIds": ["public"],
        "timeJoined": 0,
        **login_method,
    }
    return User.from_json(
        {
            "id": user_id,
            "isPrimaryUser": is_primary_user,
            "tenantIds": ["public"],
            "emails": [login_method["email"]] if "email" in login_method else [],
            "phoneNumbers": (
                [login_method["phoneNumber"]] if "phoneNumber" in login_method else []
            ),
            "thirdParty": [],
            "loginMethods": [login_method],
            "timeJoined": 0,
        }
    )


@mark.parametrize(
    "should_require_verification,primary_verified,expected_status",
    [
        (True, False, "NO_LINK"),
        (True, True, "OK"),
        (False, False, "OK"),
    ],
)
@mark.parametrize(
    "account_info",
    [
        {"recipeId": "thirdparty", "email": EMAIL},
        {"recipeId": "passwordless", "phoneNumber": "+36701234567"},
    ],
)
async def test_try_linking_checks_the_primary_users_matching_account_info(
    mocker: MockerFixture,
    should_require_verification: bool,
    primary_verified: bool,
    expected_status: str,
    account_info: Dict[str, Any],
):
    init_st(should_require_verification=should_require_verification)
    recipe = AccountLinkingRecipe.get_instance()

    input_user = make_user("input-user", False, {**account_info, "verified": True})
    primary_user = make_user(
        "primary-user", True, {**account_info, "verified": primary_verified}
    )

    mocker.patch.object(
        recipe,
        "get_primary_user_that_can_be_linked_to_recipe_user_id",
        return_value=primary_user,
    )
    link_accounts = mocker.patch.object(
        recipe.recipe_implementation,
        "link_accounts",
        return_value=mocker.Mock(
            status="OK", accounts_already_linked=False, user=primary_user
        ),
    )

    result = await recipe.try_linking_by_account_info_or_create_primary_user(
        input_user=input_user, session=None, tenant_id="public", user_context={}
    )

    assert result.status == expected_status
    assert link_accounts.called == (expected_status == "OK")
