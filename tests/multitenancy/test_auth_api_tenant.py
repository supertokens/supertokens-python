# Copyright (c) 2026, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pytest import fixture, mark
from supertokens_python import init
from supertokens_python.asyncio import list_users_by_account_info
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryInterface,
)
from supertokens_python.recipe import (
    emailpassword,
    multitenancy,
    passwordless,
    session,
    thirdparty,
)
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
    create_or_update_third_party_config,
)
from supertokens_python.recipe.multitenancy.interfaces import (
    TenantConfigCreateOrUpdate,
)
from supertokens_python.recipe.passwordless import ContactEmailOnlyConfig
from supertokens_python.recipe.passwordless.types import EmailTemplateVars
from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
)
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdparty.types import (
    ThirdPartyInfo,
    UserInfo,
    UserInfoEmail,
)
from supertokens_python.types.base import AccountInfoInput

from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio


def static_provider(third_party_id: str) -> thirdparty.ProviderInput:
    def override(original_implementation: Provider) -> Provider:
        async def get_user_info(
            oauth_tokens: Dict[str, Any],
            user_context: Dict[str, Any],
        ) -> UserInfo:
            return UserInfo(
                third_party_user_id=f"{third_party_id}-user",
                email=UserInfoEmail(f"{third_party_id}-user@example.com", True),
            )

        original_implementation.get_user_info = get_user_info
        return original_implementation

    return thirdparty.ProviderInput(
        config=thirdparty.ProviderConfig(
            third_party_id=third_party_id,
            authorization_endpoint="https://idp.example.com/auth",
            token_endpoint="https://idp.example.com/token",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id="client", client_secret="secret"
                )
            ],
        ),
        override=override,
    )


class NoopEmailService(EmailDeliveryInterface[EmailTemplateVars]):
    async def send_email(
        self, template_vars: EmailTemplateVars, user_context: Dict[str, Any]
    ) -> None:
        pass


validated_tenant_ids: List[str] = []


@fixture(scope="function")
async def client():
    validated_tenant_ids.clear()

    async def validate_email_field(value: str, tenant_id: str) -> Optional[str]:
        validated_tenant_ids.append(tenant_id)
        if tenant_id == "tenant-a" and not value.endswith("@a.example"):
            return "Only a.example emails are allowed"
        return None

    async def validate_passwordless_email(_email: str, tenant_id: str) -> Optional[str]:
        validated_tenant_ids.append(tenant_id)
        return None

    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers=[static_provider("only-b"), static_provider("in-a")]
                    )
                ),
                emailpassword.init(
                    sign_up_feature=emailpassword.InputSignUpFeature(
                        form_fields=[
                            emailpassword.InputFormField(
                                id="email", validate=validate_email_field
                            )
                        ]
                    )
                ),
                passwordless.init(
                    contact_config=ContactEmailOnlyConfig(
                        validate_email_address=validate_passwordless_email
                    ),
                    flow_type="USER_INPUT_CODE",
                    email_delivery=EmailDeliveryConfig(service=NoopEmailService()),
                ),
                session.init(get_token_transfer_method=lambda *_: "header"),  # type: ignore
                multitenancy.init(),
            ],
        )
    )

    first_factors = ["emailpassword", "thirdparty", "otp-email"]
    await create_or_update_tenant(
        "tenant-a", TenantConfigCreateOrUpdate(first_factors=first_factors)
    )
    await create_or_update_tenant(
        "tenant-b", TenantConfigCreateOrUpdate(first_factors=first_factors)
    )
    await create_or_update_third_party_config(
        "tenant-a",
        thirdparty.ProviderConfig(
            third_party_id="in-a",
            name="In A",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id="client", client_secret="secret"
                )
            ],
        ),
    )
    await create_or_update_third_party_config(
        "tenant-b",
        thirdparty.ProviderConfig(
            third_party_id="only-b",
            name="Only B",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id="client", client_secret="secret"
                )
            ],
        ),
    )

    app = FastAPI()
    app.add_middleware(get_middleware())
    return TestClient(app)


async def get_access_token_in_tenant(tenant_id: str) -> str:
    sign_up_res = await sign_up(
        tenant_id, f"session-user@{tenant_id}.example", "password123"
    )
    assert isinstance(sign_up_res, SignUpOkResult)
    new_session = await create_new_session_without_request_response(
        tenant_id, sign_up_res.user.login_methods[0].recipe_user_id
    )
    validated_tenant_ids.clear()
    return new_session.get_all_session_tokens_dangerously()["accessToken"]


def get_headers(access_token: Optional[str] = None) -> Dict[str, str]:
    # FDI 3.0 loads the session optionally, so it is used if present
    headers = {"fdi-version": "3.0"}
    if access_token is not None:
        headers["Authorization"] = f"Bearer {access_token}"
    return headers


async def get_third_party_users(tenant_id: str, third_party_id: str):
    return await list_users_by_account_info(
        tenant_id,
        AccountInfoInput(
            third_party=ThirdPartyInfo(
                third_party_user_id=f"{third_party_id}-user",
                third_party_id=third_party_id,
            )
        ),
    )


async def test_thirdparty_signinup_does_not_use_a_provider_only_the_path_tenant_has_for_the_session_tenant(
    client: TestClient,
):
    access_token = await get_access_token_in_tenant("tenant-a")

    res = client.post(
        "/auth/tenant-b/signinup",
        headers=get_headers(access_token),
        json={"thirdPartyId": "only-b", "oAuthTokens": {"access_token": "token"}},
    )

    assert res.status_code == 400
    assert (
        res.json()["message"]
        == "the provider only-b could not be found in the configuration"
    )
    assert len(await get_third_party_users("tenant-a", "only-b")) == 0
    assert len(await get_third_party_users("tenant-b", "only-b")) == 0


async def test_thirdparty_signinup_signs_in_to_the_session_tenant_with_its_own_provider(
    client: TestClient,
):
    access_token = await get_access_token_in_tenant("tenant-a")

    res = client.post(
        "/auth/tenant-b/signinup",
        headers=get_headers(access_token),
        json={"thirdPartyId": "in-a", "oAuthTokens": {"access_token": "token"}},
    )

    assert res.status_code == 200
    assert res.json()["status"] == "OK"
    assert res.json()["user"]["loginMethods"][0]["tenantIds"] == ["tenant-a"]


async def test_thirdparty_signinup_uses_the_path_tenant_provider_without_a_session(
    client: TestClient,
):
    res = client.post(
        "/auth/tenant-b/signinup",
        headers=get_headers(),
        json={"thirdPartyId": "only-b", "oAuthTokens": {"access_token": "token"}},
    )

    assert res.status_code == 200
    assert res.json()["status"] == "OK"
    assert res.json()["user"]["loginMethods"][0]["tenantIds"] == ["tenant-b"]


async def test_thirdparty_signinup_uses_the_path_tenant_provider_with_a_session_in_the_same_tenant(
    client: TestClient,
):
    access_token = await get_access_token_in_tenant("tenant-b")

    res = client.post(
        "/auth/tenant-b/signinup",
        headers=get_headers(access_token),
        json={"thirdPartyId": "only-b", "oAuthTokens": {"access_token": "token"}},
    )

    assert res.status_code == 200
    assert res.json()["status"] == "OK"
    assert res.json()["user"]["loginMethods"][0]["tenantIds"] == ["tenant-b"]


async def test_emailpassword_signup_runs_the_session_tenant_validators(
    client: TestClient,
):
    access_token = await get_access_token_in_tenant("tenant-a")

    res = client.post(
        "/auth/tenant-b/signup",
        headers=get_headers(access_token),
        json={
            "formFields": [
                {"id": "email", "value": "someone@other.example"},
                {"id": "password", "value": "password123"},
            ]
        },
    )

    assert res.status_code == 200
    assert res.json()["status"] == "FIELD_ERROR"
    assert validated_tenant_ids == ["tenant-a"]
    users = await list_users_by_account_info(
        "tenant-a", AccountInfoInput(email="someone@other.example")
    )
    assert len(users) == 0


async def test_emailpassword_signin_runs_the_session_tenant_validators(
    client: TestClient,
):
    access_token = await get_access_token_in_tenant("tenant-a")

    client.post(
        "/auth/tenant-b/signin",
        headers=get_headers(access_token),
        json={
            "formFields": [
                {"id": "email", "value": "session-user@tenant-a.example"},
                {"id": "password", "value": "password123"},
            ]
        },
    )

    assert validated_tenant_ids == ["tenant-a"]


async def test_emailpassword_signup_runs_the_path_tenant_validators_without_a_session(
    client: TestClient,
):
    res = client.post(
        "/auth/tenant-b/signup",
        headers=get_headers(),
        json={
            "formFields": [
                {"id": "email", "value": "someone@other.example"},
                {"id": "password", "value": "password123"},
            ]
        },
    )

    assert res.status_code == 200
    assert res.json()["status"] == "OK"
    assert validated_tenant_ids == ["tenant-b"]


async def test_emailpassword_signup_runs_the_path_tenant_validators_with_a_session_in_the_same_tenant(
    client: TestClient,
):
    access_token = await get_access_token_in_tenant("tenant-a")

    res = client.post(
        "/auth/tenant-a/signup",
        headers=get_headers(access_token),
        json={
            "formFields": [
                {"id": "email", "value": "someone@other.example"},
                {"id": "password", "value": "password123"},
            ]
        },
    )

    assert res.status_code == 200
    assert res.json()["status"] == "FIELD_ERROR"
    assert validated_tenant_ids == ["tenant-a"]


async def test_passwordless_create_code_runs_the_session_tenant_email_validator(
    client: TestClient,
):
    access_token = await get_access_token_in_tenant("tenant-a")

    res = client.post(
        "/auth/tenant-b/signinup/code",
        headers=get_headers(access_token),
        json={"email": "someone@other.example"},
    )

    assert res.status_code == 200
    assert validated_tenant_ids == ["tenant-a"]


async def test_passwordless_create_code_runs_the_path_tenant_email_validator_without_a_session(
    client: TestClient,
):
    res = client.post(
        "/auth/tenant-b/signinup/code",
        headers=get_headers(),
        json={"email": "someone@other.example"},
    )

    assert res.status_code == 200
    assert res.json()["status"] == "OK"
    assert validated_tenant_ids == ["tenant-b"]
