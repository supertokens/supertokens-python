from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pytest import fixture, mark
from supertokens_python import init
from supertokens_python.asyncio import list_users_by_account_info
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import (
    emailpassword,
    multifactorauth,
    multitenancy,
    passwordless,
    session,
)
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.recipe.multifactorauth.types import FactorIds
from supertokens_python.recipe.multifactorauth.utils import is_valid_first_factor
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
    get_tenant,
)
from supertokens_python.recipe.multitenancy.interfaces import (
    TenantConfigCreateOrUpdate,
)
from supertokens_python.types.base import AccountInfoInput

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio


@fixture(scope="function")
def client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


class NoopEmailService(
    passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
):
    async def send_email(
        self,
        template_vars: passwordless.EmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        pass


def setup(static_first_factors: Optional[List[str]] = None):
    recipe_list: List[Any] = [
        session.init(get_token_transfer_method=lambda *_: "header"),  # type: ignore
        emailpassword.init(),
        passwordless.init(
            contact_config=passwordless.ContactEmailOnlyConfig(),
            flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
            email_delivery=passwordless.EmailDeliveryConfig(NoopEmailService()),
        ),
        multitenancy.init(),
    ]
    if static_first_factors is not None:
        recipe_list.append(multifactorauth.init(first_factors=static_first_factors))
    init(**get_st_init_args(url=get_new_core_app_url(), recipe_list=recipe_list))


async def create_tenant_with_no_first_factors(tenant_id: str):
    await create_or_update_tenant(
        tenant_id, TenantConfigCreateOrUpdate(first_factors=[])
    )
    tenant = await get_tenant(tenant_id)
    assert tenant is not None
    assert tenant.first_factors == []


async def test_tenant_with_no_first_factors_rejects_every_first_factor():
    setup()
    await create_tenant_with_no_first_factors("locked")

    for factor_id in FactorIds.get_all_factors():
        assert (
            await is_valid_first_factor("locked", factor_id, {})
            == "INVALID_FIRST_FACTOR_ERROR"
        )


async def test_tenant_with_no_first_factors_ignores_static_first_factors():
    setup(static_first_factors=["emailpassword"])
    await create_tenant_with_no_first_factors("locked")

    assert (
        await is_valid_first_factor("locked", "emailpassword", {})
        == "INVALID_FIRST_FACTOR_ERROR"
    )


async def test_tenant_with_no_first_factors_rejects_sign_up(client: TestClient):
    setup()
    await create_tenant_with_no_first_factors("locked")

    res = client.post(
        "/auth/locked/signup",
        json={
            "formFields": [
                {"id": "email", "value": "user@example.com"},
                {"id": "password", "value": "password123"},
            ]
        },
    )

    assert res.status_code == 401
    users = await list_users_by_account_info(
        "locked", AccountInfoInput(email="user@example.com")
    )
    assert users == []


async def test_tenant_with_no_first_factors_rejects_sign_in(client: TestClient):
    setup()
    await create_or_update_tenant(
        "locked", TenantConfigCreateOrUpdate(first_factors=["emailpassword"])
    )
    sign_up_res = await sign_up("locked", "user@example.com", "password123")
    assert isinstance(sign_up_res, SignUpOkResult)
    await create_tenant_with_no_first_factors("locked")

    res = client.post(
        "/auth/locked/signin",
        json={
            "formFields": [
                {"id": "email", "value": "user@example.com"},
                {"id": "password", "value": "password123"},
            ]
        },
    )

    assert res.status_code == 401
    # no session is created
    assert res.headers.get("st-access-token", "") == ""


async def test_tenant_with_no_first_factors_rejects_passwordless_sign_in_up(
    client: TestClient,
):
    setup()
    await create_tenant_with_no_first_factors("locked")

    res = client.post("/auth/locked/signinup/code", json={"email": "user@example.com"})

    assert res.status_code == 401


async def test_tenant_with_unset_first_factors_allows_every_initialised_first_factor(
    client: TestClient,
):
    setup()
    await create_or_update_tenant(
        "open", TenantConfigCreateOrUpdate(first_factors=None)
    )
    tenant = await get_tenant("open")
    assert tenant is not None
    assert tenant.first_factors is None

    assert await is_valid_first_factor("open", "emailpassword", {}) == "OK"
    assert await is_valid_first_factor("open", "otp-email", {}) == "OK"

    res = client.post(
        "/auth/open/signup",
        json={
            "formFields": [
                {"id": "email", "value": "user@example.com"},
                {"id": "password", "value": "password123"},
            ]
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "OK"
