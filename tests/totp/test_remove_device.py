from typing import Any, Awaitable, Callable, Dict, List

import pyotp
from fastapi import FastAPI
from pytest import fixture, mark
from supertokens_python import init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import emailpassword, multifactorauth, session, totp
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.recipe.multifactorauth.asyncio import (
    mark_factor_as_complete_in_session,
)
from supertokens_python.recipe.multifactorauth.interfaces import (
    RecipeInterface as MFARecipeInterface,
)
from supertokens_python.recipe.multifactorauth.types import (
    MFARequirementList,
    MultiFactorAuthOverrideConfig,
)
from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
)
from supertokens_python.recipe.totp.asyncio import create_device, verify_device
from supertokens_python.recipe.totp.interfaces import (
    RecipeInterface as TOTPRecipeInterface,
)
from supertokens_python.recipe.totp.types import (
    CreateDeviceOkResult,
    RemoveDeviceOkResult,
    TOTPConfig,
    TOTPOverrideConfig,
    VerifyDeviceOkResult,
)
from supertokens_python.types import User

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

USER_EMAIL = "user@example.com"


@fixture(scope="function")
def app():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


@fixture(scope="function")
def remove_device_calls() -> List[str]:
    calls: List[str] = []

    def override_mfa_functions(oi: MFARecipeInterface) -> MFARecipeInterface:
        async def get_mfa_requirements_for_auth(
            tenant_id: str,
            access_token_payload: Dict[str, Any],
            completed_factors: Dict[str, int],
            user: Callable[[], Awaitable[User]],
            factors_set_up_for_user: Callable[[], Awaitable[List[str]]],
            required_secondary_factors_for_user: Callable[[], Awaitable[List[str]]],
            required_secondary_factors_for_tenant: Callable[[], Awaitable[List[str]]],
            user_context: Dict[str, Any],
        ) -> MFARequirementList:
            return ["totp"]

        oi.get_mfa_requirements_for_auth = get_mfa_requirements_for_auth
        return oi

    def override_totp_functions(oi: TOTPRecipeInterface) -> TOTPRecipeInterface:
        original_remove_device = oi.remove_device

        async def remove_device(
            user_id: str, device_name: str, user_context: Dict[str, Any]
        ) -> RemoveDeviceOkResult:
            calls.append(device_name)
            return await original_remove_device(user_id, device_name, user_context)

        oi.remove_device = remove_device
        return oi

    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                emailpassword.init(),
                session.init(get_token_transfer_method=lambda _, __, ___: "header"),
                multifactorauth.init(
                    first_factors=["emailpassword"],
                    override=MultiFactorAuthOverrideConfig(
                        functions=override_mfa_functions
                    ),
                ),
                totp.init(
                    TOTPConfig(
                        override=TOTPOverrideConfig(functions=override_totp_functions)
                    )
                ),
            ],
        )
    )

    return calls


async def create_user() -> User:
    res = await sign_up("public", USER_EMAIL, "password123")
    assert isinstance(res, SignUpOkResult)
    return res.user


async def create_totp_device(user: User, device_name: str, verified: bool):
    res = await create_device(user.id, USER_EMAIL, device_name)
    assert isinstance(res, CreateDeviceOkResult)
    if verified:
        verify_res = await verify_device(
            "public", user.id, device_name, pyotp.TOTP(res.secret).now()
        )
        assert isinstance(verify_res, VerifyDeviceOkResult)


async def get_access_token(user: User, complete_totp: bool = False) -> str:
    s = await create_new_session_without_request_response(
        "public", user.login_methods[0].recipe_user_id
    )
    if complete_totp:
        await mark_factor_as_complete_in_session(s, "totp")
    return s.get_all_session_tokens_dangerously()["accessToken"]


def remove_device_request(app: TestClient, access_token: str, device_name: str):
    return app.post(
        "/auth/totp/device/remove",
        headers={"authorization": f"Bearer {access_token}"},
        json={"deviceName": device_name},
    )


def assert_mfa_required(res: Any, remove_device_calls: List[str]):
    assert res.status_code == 403, res.text
    body = res.json()
    assert body["message"] == "invalid claim"
    assert body["claimValidationErrors"][0]["id"] == "st-mfa"
    assert remove_device_calls == []


@mark.parametrize(
    "device_name",
    [
        "phone",
        "PHONE",
        # fullwidth letters, equal to "Phone" after NFKC normalisation
        "Ｐｈｏｎｅ",
        "Phone",
    ],
)
async def test_removing_a_name_matching_a_verified_device_requires_mfa(
    app: TestClient, remove_device_calls: List[str], device_name: str
):
    user = await create_user()
    await create_totp_device(user, "Phone", verified=True)
    access_token = await get_access_token(user)

    res = remove_device_request(app, access_token, device_name)

    assert_mfa_required(res, remove_device_calls)


async def test_removing_an_unknown_device_requires_mfa_if_a_verified_device_exists(
    app: TestClient, remove_device_calls: List[str]
):
    user = await create_user()
    await create_totp_device(user, "Phone", verified=True)
    access_token = await get_access_token(user)

    res = remove_device_request(app, access_token, "Tablet")

    assert_mfa_required(res, remove_device_calls)


async def test_removing_an_unverified_device_matching_a_verified_device_requires_mfa(
    app: TestClient, remove_device_calls: List[str]
):
    user = await create_user()
    await create_totp_device(user, "Phone", verified=True)
    await create_totp_device(user, "PHONE", verified=False)
    access_token = await get_access_token(user)

    res = remove_device_request(app, access_token, "PHONE")

    assert_mfa_required(res, remove_device_calls)


async def test_a_lone_unverified_device_can_be_removed_without_mfa(
    app: TestClient, remove_device_calls: List[str]
):
    user = await create_user()
    await create_totp_device(user, "Pending", verified=False)
    access_token = await get_access_token(user)

    res = remove_device_request(app, access_token, "Pending")

    assert res.status_code == 200, res.text
    assert res.json() == {"status": "OK", "didDeviceExist": True}
    assert remove_device_calls == ["Pending"]


async def test_an_unverified_device_can_be_removed_without_mfa_if_no_verified_device_matches(
    app: TestClient, remove_device_calls: List[str]
):
    user = await create_user()
    await create_totp_device(user, "Phone", verified=True)
    await create_totp_device(user, "Pending", verified=False)
    access_token = await get_access_token(user)

    res = remove_device_request(app, access_token, "Pending")

    assert res.status_code == 200, res.text
    assert res.json() == {"status": "OK", "didDeviceExist": True}
    assert remove_device_calls == ["Pending"]


async def test_a_verified_device_can_be_removed_with_mfa_completed(
    app: TestClient, remove_device_calls: List[str]
):
    user = await create_user()
    await create_totp_device(user, "Phone", verified=True)
    access_token = await get_access_token(user, complete_totp=True)

    res = remove_device_request(app, access_token, "Phone")

    assert res.status_code == 200, res.text
    assert res.json() == {"status": "OK", "didDeviceExist": True}
    assert remove_device_calls == ["Phone"]
