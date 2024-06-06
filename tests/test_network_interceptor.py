from typing import Dict, Any, Optional

import pytest
from fastapi import FastAPI
from tests.testclient import TestClientWithNoCookieJar as TestClient
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session, emailpassword, userroles
from supertokens_python.recipe.emailpassword.asyncio import sign_in, sign_up
from supertokens_python.recipe.userroles.asyncio import get_roles_for_user
from tests.utils import clean_st, reset, setup_st, start_st


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


@fixture(scope="function")
async def driver_config_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app, raise_server_exceptions=False)


@mark.asyncio
async def test_network_interceptor_sanity(driver_config_client: TestClient):
    is_network_intercepted = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        _: Optional[Dict[str, Any]],
    ):
        nonlocal is_network_intercepted
        is_network_intercepted = True
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            "http://localhost:3567", network_interceptor=intercept
        ),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()
    resp = driver_config_client.post(
        url="/auth/signin",
        json={
            "formFields": [
                {
                    "id": "email",
                    "value": "testEmail@email.com",
                },
                {
                    "id": "password",
                    "value": "validPassword123",
                },
            ]
        },
    )

    assert is_network_intercepted is True
    assert resp.status_code == 200


@mark.asyncio
async def test_network_interceptor_incorrect_core_url():
    is_network_intercepted = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        __: Optional[Dict[str, Any]],
    ):
        nonlocal is_network_intercepted
        is_network_intercepted = True
        url = url + "/incorrect/url"
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            "http://localhost:3567", network_interceptor=intercept
        ),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()
    with pytest.raises(Exception) as err:
        await sign_up("public", "testEmail@email.com", "validPassword123")
    assert "status code: 404" in str(err)

    assert is_network_intercepted is True


@mark.asyncio
async def test_network_interceptor_incorrect_query_params():
    is_network_intercepted = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        body: Optional[Dict[str, Any]],
        __: Optional[Dict[str, Any]],
    ):
        nonlocal is_network_intercepted
        is_network_intercepted = True
        params = {}
        return url, method, headers, params, body

    init(
        supertokens_config=SupertokensConfig(
            "http://localhost:3567", network_interceptor=intercept
        ),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            userroles.init(),
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()
    with pytest.raises(Exception) as err:
        await get_roles_for_user("public", "someUserId")
    assert "status code: 400" in str(err)

    assert is_network_intercepted is True


@mark.asyncio
async def test_network_interceptor_incorrect_request_body():
    is_network_intercepted = False

    def intercept(
        url: str,
        method: str,
        headers: Dict[str, Any],
        params: Optional[Dict[str, Any]],
        _: Optional[Dict[str, Any]],
        __: Optional[Dict[str, Any]],
    ):
        nonlocal is_network_intercepted
        is_network_intercepted = True
        newBody = {"newKey": "newValue"}
        return url, method, headers, params, newBody

    init(
        supertokens_config=SupertokensConfig(
            "http://localhost:3567", network_interceptor=intercept
        ),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            emailpassword.init(),
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie"),
        ],
    )
    start_st()

    with pytest.raises(Exception) as err:
        await sign_in("public", "testEmail@email.com", "validPassword123")
    assert "status code: 400" in str(err)

    assert is_network_intercepted is True
