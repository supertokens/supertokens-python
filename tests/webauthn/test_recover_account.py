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
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
from pytest import mark
from supertokens_python import init
from supertokens_python.asyncio import get_user, list_users_by_account_info
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryInterface,
)
from supertokens_python.recipe import (
    accountlinking,
    emailpassword,
    emailverification,
    session,
    webauthn,
)
from supertokens_python.recipe.accountlinking.asyncio import (
    create_primary_user,
    link_accounts,
)
from supertokens_python.recipe.accountlinking.types import (
    AccountInfoWithRecipeIdAndUserId,
    ShouldAutomaticallyLink,
    ShouldNotAutomaticallyLink,
)
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.recipe.emailverification.asyncio import (
    create_email_verification_token,
    unverify_email,
    verify_email_using_token,
)
from supertokens_python.recipe.emailverification.interfaces import (
    CreateEmailVerificationTokenOkResult,
    VerifyEmailUsingTokenOkResult,
)
from supertokens_python.recipe.emailverification.types import (
    EmailTemplateVars as EmailVerificationTemplateVars,
)
from supertokens_python.recipe.session.asyncio import (
    get_session_information,
    get_session_without_request_response,
)
from supertokens_python.recipe.session.interfaces import (
    SessionClaimValidator,
    SessionContainer,
)
from supertokens_python.recipe.webauthn.functions import list_credentials
from supertokens_python.recipe.webauthn.interfaces.api import (
    TypeWebauthnEmailDeliveryInput,
)
from supertokens_python.recipe.webauthn.types.config import WebauthnConfig
from supertokens_python.types.base import AccountInfoInput, RecipeUserId, User
from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url, get_st_init_args
from tests.webauthn.soft_authenticator import SoftAuthenticator, b64url

pytestmark = mark.asyncio

RP_ID = "supertokens.io"
ORIGIN = "https://supertokens.io"

recover_account_tokens: Dict[str, str] = {}


class RecoverAccountEmailService(
    EmailDeliveryInterface[TypeWebauthnEmailDeliveryInput]
):
    async def send_email(
        self,
        template_vars: TypeWebauthnEmailDeliveryInput,
        user_context: Dict[str, Any],
    ) -> None:
        query = parse_qs(urlparse(template_vars.recover_account_link).query)
        recover_account_tokens[template_vars.user.email] = query["token"][0]


class NoopEmailVerificationService(
    EmailDeliveryInterface[EmailVerificationTemplateVars]
):
    async def send_email(
        self,
        template_vars: EmailVerificationTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        pass


async def should_link(
    _account_info: AccountInfoWithRecipeIdAndUserId,
    _user: Optional[User],
    _session: Optional[SessionContainer],
    _tenant_id: str,
    user_context: Dict[str, Any],
) -> Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink]:
    if user_context.get("do_not_link") is True:
        return ShouldNotAutomaticallyLink()
    return ShouldAutomaticallyLink(should_require_verification=True)


async def get_rp_id(**_: Any) -> str:
    return RP_ID


async def get_origin(**_: Any) -> str:
    return ORIGIN


def init_st_and_get_client(account_linking: bool = True) -> TestClient:
    recover_account_tokens.clear()
    recipe_list: List[Any] = [
        # webauthn is listed before emailpassword so that /webauthn/signup is not
        # routed to the emailpassword sign up API of a tenant called "webauthn"
        webauthn.init(
            config=WebauthnConfig(
                get_relying_party_id=get_rp_id,
                get_origin=get_origin,
                email_delivery=EmailDeliveryConfig(
                    service=RecoverAccountEmailService()
                ),
            )
        ),
        emailpassword.init(),
        emailverification.init(
            mode="REQUIRED",
            email_delivery=EmailDeliveryConfig(service=NoopEmailVerificationService()),
        ),
        session.init(get_token_transfer_method=lambda *_: "header"),  # type: ignore
    ]
    if account_linking:
        recipe_list.append(
            accountlinking.init(should_do_automatic_account_linking=should_link)
        )
    init(**get_st_init_args(url=get_new_core_app_url(), recipe_list=recipe_list))

    app = FastAPI()
    app.add_middleware(get_middleware())
    return TestClient(app)


def post(
    client: TestClient, path: str, body: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    res = client.post(path, json=body)
    assert res.status_code == 200, f"{path} returned {res.status_code}: {res.text}"
    return res.json(), dict(res.headers)


def new_authenticator() -> SoftAuthenticator:
    return SoftAuthenticator(rp_id=RP_ID, origin=ORIGIN)


async def verify_email(recipe_user_id: RecipeUserId, email: str):
    token_res = await create_email_verification_token("public", recipe_user_id, email)
    assert isinstance(token_res, CreateEmailVerificationTokenOkResult)
    verify_res = await verify_email_using_token("public", token_res.token, False)
    assert isinstance(verify_res, VerifyEmailUsingTokenOkResult)


async def create_verified_primary_emailpassword_user(email: str) -> RecipeUserId:
    sign_up_res = await sign_up("public", email, "password123")
    assert isinstance(sign_up_res, SignUpOkResult)
    recipe_user_id = sign_up_res.user.login_methods[0].recipe_user_id
    await verify_email(recipe_user_id, email)
    user = await get_user(recipe_user_id.get_as_string())
    assert user is not None
    if not user.is_primary_user:
        primary_res = await create_primary_user(recipe_user_id)
        assert primary_res.status == "OK"
    return recipe_user_id


def webauthn_sign_up(
    client: TestClient, authenticator: SoftAuthenticator, email: str
) -> Dict[str, Any]:
    register_options, _ = post(
        client, "/auth/webauthn/options/register", {"email": email}
    )
    assert register_options["status"] == "OK"
    body, headers = post(
        client,
        "/auth/webauthn/signup",
        {
            "credential": authenticator.create_attestation(register_options),
            "webauthnGeneratedOptionsId": register_options[
                "webauthnGeneratedOptionsId"
            ],
            "shouldTryLinkingWithSessionUser": False,
        },
    )
    assert body["status"] == "OK", body
    return {
        "user": body["user"],
        "user_handle": register_options["user"]["id"],
        "access_token": headers["st-access-token"],
    }


def webauthn_sign_in(
    client: TestClient, authenticator: SoftAuthenticator, user_handle: str
) -> Dict[str, Any]:
    sign_in_options, _ = post(client, "/auth/webauthn/options/signin", {})
    assert sign_in_options["status"] == "OK"
    body, _ = post(
        client,
        "/auth/webauthn/signin",
        {
            "credential": authenticator.create_assertion(
                sign_in_options, sign_count=0, user_handle=user_handle
            ),
            "webauthnGeneratedOptionsId": sign_in_options["webauthnGeneratedOptionsId"],
            "shouldTryLinkingWithSessionUser": False,
        },
    )
    return body


def request_recover_account_token(client: TestClient, email: str) -> str:
    body, _ = post(client, "/auth/user/webauthn/reset/token", {"email": email})
    assert body["status"] == "OK"
    assert email in recover_account_tokens, f"no recover account email sent to {email}"
    return recover_account_tokens[email]


def get_register_options_for_token(client: TestClient, token: str) -> Dict[str, Any]:
    register_options, _ = post(
        client, "/auth/webauthn/options/register", {"recoverAccountToken": token}
    )
    assert register_options["status"] == "OK"
    return register_options


def recover_account(
    client: TestClient,
    token: str,
    register_options: Dict[str, Any],
    authenticator: SoftAuthenticator,
) -> Dict[str, Any]:
    body, _ = post(
        client,
        "/auth/user/webauthn/reset",
        {
            "token": token,
            "webauthnGeneratedOptionsId": register_options[
                "webauthnGeneratedOptionsId"
            ],
            "credential": authenticator.create_attestation(register_options),
        },
    )
    return body


async def get_webauthn_users_for_email(email: str) -> List[User]:
    users = await list_users_by_account_info("public", AccountInfoInput(email=email))
    return [
        u
        for u in users
        if any(
            lm.recipe_id == "webauthn" and lm.has_same_email_as(email)
            for lm in u.login_methods
        )
    ]


async def get_credential_ids(recipe_user_id: str) -> List[str]:
    res = await list_credentials(recipe_user_id=recipe_user_id)
    assert res.status == "OK"
    return sorted(c.webauthn_credential_id for c in res.credentials)


async def get_session_handle(access_token: str) -> str:
    def no_claim_validators(*_: Any) -> List[SessionClaimValidator]:
        return []

    session_container = await get_session_without_request_response(
        access_token, override_global_claim_validators=no_claim_validators
    )
    assert session_container is not None
    return session_container.get_handle()


async def test_recover_account_with_options_for_another_email_does_not_create_a_webauthn_user():
    client = init_st_and_get_client()
    await create_verified_primary_emailpassword_user("owner@example.com")
    await create_verified_primary_emailpassword_user("other@example.com")

    token = request_recover_account_token(client, "owner@example.com")
    register_options, _ = post(
        client, "/auth/webauthn/options/register", {"email": "other@example.com"}
    )
    assert register_options["status"] == "OK"

    res = recover_account(client, token, register_options, new_authenticator())

    assert res["status"] == "INVALID_OPTIONS_ERROR"
    assert len(await get_webauthn_users_for_email("other@example.com")) == 0
    assert len(await get_webauthn_users_for_email("owner@example.com")) == 0


async def test_recover_account_with_options_for_another_email_does_not_register_a_credential():
    client = init_st_and_get_client()
    signed_up = webauthn_sign_up(client, new_authenticator(), "owner@example.com")
    recipe_user_id = signed_up["user"]["loginMethods"][0]["recipeUserId"]
    credentials_before = await get_credential_ids(recipe_user_id)

    token = request_recover_account_token(client, "owner@example.com")
    register_options, _ = post(
        client, "/auth/webauthn/options/register", {"email": "other@example.com"}
    )

    res = recover_account(client, token, register_options, new_authenticator())

    assert res["status"] == "INVALID_OPTIONS_ERROR"
    assert await get_credential_ids(recipe_user_id) == credentials_before


async def test_recover_account_compares_the_option_and_token_emails_case_insensitively():
    client = init_st_and_get_client()
    webauthn_sign_up(client, new_authenticator(), "owner@example.com")

    token = request_recover_account_token(client, "owner@example.com")
    register_options, _ = post(
        client, "/auth/webauthn/options/register", {"email": "Owner@Example.com"}
    )

    res = recover_account(client, token, register_options, new_authenticator())

    assert res["status"] == "OK"


async def test_recover_account_does_not_create_a_webauthn_user_if_sign_up_is_not_allowed():
    client = init_st_and_get_client()
    recipe_user_id = await create_verified_primary_emailpassword_user(
        "owner@example.com"
    )
    token = request_recover_account_token(client, "owner@example.com")
    register_options = get_register_options_for_token(client, token)

    # the primary user's email is no longer verified when the token is used
    await unverify_email(recipe_user_id, "owner@example.com")

    res = recover_account(client, token, register_options, new_authenticator())

    assert res["status"] == "RECOVER_ACCOUNT_TOKEN_INVALID_ERROR"
    assert len(await get_webauthn_users_for_email("owner@example.com")) == 0


async def test_recover_account_creates_and_links_a_webauthn_user_if_sign_up_is_allowed():
    client = init_st_and_get_client()
    recipe_user_id = await create_verified_primary_emailpassword_user(
        "owner@example.com"
    )
    token = request_recover_account_token(client, "owner@example.com")
    register_options = get_register_options_for_token(client, token)

    res = recover_account(client, token, register_options, new_authenticator())

    assert res["status"] == "OK"
    primary_user = await get_user(recipe_user_id.get_as_string())
    assert primary_user is not None
    assert len(primary_user.login_methods) == 2
    assert any(
        lm.recipe_id == "webauthn" and lm.verified for lm in primary_user.login_methods
    )


@mark.parametrize("account_linking", [True, False])
async def test_recover_account_of_an_unverified_webauthn_user_removes_earlier_credentials_and_sessions(
    account_linking: bool,
):
    client = init_st_and_get_client(account_linking=account_linking)
    earlier_authenticator = new_authenticator()
    earlier = webauthn_sign_up(client, earlier_authenticator, "owner@example.com")
    recipe_user_id = earlier["user"]["loginMethods"][0]["recipeUserId"]
    earlier_session_handle = await get_session_handle(earlier["access_token"])

    token = request_recover_account_token(client, "owner@example.com")
    register_options = get_register_options_for_token(client, token)
    recovering_authenticator = new_authenticator()
    res = recover_account(client, token, register_options, recovering_authenticator)
    assert res["status"] == "OK"

    user = await get_user(recipe_user_id)
    assert user is not None
    login_method = next(
        lm
        for lm in user.login_methods
        if lm.recipe_user_id.get_as_string() == recipe_user_id
    )
    assert login_method.verified is True

    assert await get_credential_ids(recipe_user_id) == [
        b64url(recovering_authenticator.credential_id)
    ]
    assert await get_session_information(earlier_session_handle) is None

    earlier_sign_in = webauthn_sign_in(
        client, earlier_authenticator, earlier["user_handle"]
    )
    assert earlier_sign_in["status"] != "OK"

    recovered_sign_in = webauthn_sign_in(
        client, recovering_authenticator, register_options["user"]["id"]
    )
    assert recovered_sign_in["status"] == "OK"


async def test_recover_account_of_a_verified_webauthn_user_keeps_other_credentials_and_sessions():
    client = init_st_and_get_client()
    first_authenticator = new_authenticator()
    first = webauthn_sign_up(client, first_authenticator, "owner@example.com")
    recipe_user_id = first["user"]["loginMethods"][0]["recipeUserId"]
    await verify_email(RecipeUserId(recipe_user_id), "owner@example.com")
    first_session_handle = await get_session_handle(first["access_token"])

    token = request_recover_account_token(client, "owner@example.com")
    register_options = get_register_options_for_token(client, token)
    second_authenticator = new_authenticator()
    res = recover_account(client, token, register_options, second_authenticator)
    assert res["status"] == "OK"

    assert await get_credential_ids(recipe_user_id) == sorted(
        [
            b64url(first_authenticator.credential_id),
            b64url(second_authenticator.credential_id),
        ]
    )
    assert await get_session_information(first_session_handle) is not None
    assert (
        webauthn_sign_in(client, first_authenticator, first["user_handle"])["status"]
        == "OK"
    )


async def recover_after_earlier_sign_up(
    account_linking: bool,
) -> Tuple[TestClient, str, str, SoftAuthenticator]:
    client = init_st_and_get_client(account_linking=account_linking)
    earlier = webauthn_sign_up(client, new_authenticator(), "owner@example.com")
    recipe_user_id = earlier["user"]["loginMethods"][0]["recipeUserId"]

    token = request_recover_account_token(client, "owner@example.com")
    register_options = get_register_options_for_token(client, token)
    recovering_authenticator = new_authenticator()
    res = recover_account(client, token, register_options, recovering_authenticator)
    assert res["status"] == "OK"

    return client, earlier["access_token"], recipe_user_id, recovering_authenticator


@mark.parametrize("account_linking", [True, False])
async def test_sessions_from_before_recovery_cannot_register_credentials(
    account_linking: bool,
):
    (
        client,
        earlier_access_token,
        recipe_user_id,
        _,
    ) = await recover_after_earlier_sign_up(account_linking)
    credentials_after_recovery = await get_credential_ids(recipe_user_id)

    register_options, _ = post(
        client, "/auth/webauthn/options/register", {"email": "owner@example.com"}
    )
    assert register_options["status"] == "OK"
    res = client.post(
        "/auth/webauthn/credential",
        json={
            "webauthnGeneratedOptionsId": register_options[
                "webauthnGeneratedOptionsId"
            ],
            "credential": new_authenticator().create_attestation(register_options),
        },
        headers={"Authorization": f"Bearer {earlier_access_token}"},
    )

    assert res.status_code == 401
    assert await get_credential_ids(recipe_user_id) == credentials_after_recovery


@mark.parametrize("account_linking", [True, False])
async def test_sessions_from_before_recovery_cannot_remove_credentials(
    account_linking: bool,
):
    (
        client,
        earlier_access_token,
        recipe_user_id,
        recovering_authenticator,
    ) = await recover_after_earlier_sign_up(account_linking)

    res = client.post(
        "/auth/webauthn/credential/remove",
        json={"webauthnCredentialId": b64url(recovering_authenticator.credential_id)},
        headers={"Authorization": f"Bearer {earlier_access_token}"},
    )

    assert res.status_code == 401
    assert await get_credential_ids(recipe_user_id) == [
        b64url(recovering_authenticator.credential_id)
    ]


@mark.parametrize("account_linking", [True, False])
async def test_sessions_from_before_recovery_cannot_list_credentials(
    account_linking: bool,
):
    (
        client,
        earlier_access_token,
        _,
        _,
    ) = await recover_after_earlier_sign_up(account_linking)

    res = client.get(
        "/auth/webauthn/credential/list",
        headers={"Authorization": f"Bearer {earlier_access_token}"},
    )

    assert res.status_code == 401


async def test_sessions_from_before_recovery_cannot_link_new_login_methods():
    (
        client,
        earlier_access_token,
        _,
        _,
    ) = await recover_after_earlier_sign_up(account_linking=True)

    res = client.post(
        "/auth/signup",
        json={
            "formFields": [
                {"id": "email", "value": "someone-else@example.com"},
                {"id": "password", "value": "password123"},
            ],
            "shouldTryLinkingWithSessionUser": True,
        },
        headers={"Authorization": f"Bearer {earlier_access_token}"},
    )

    assert res.status_code == 401
    assert (
        len(
            await list_users_by_account_info(
                "public", AccountInfoInput(email="someone-else@example.com")
            )
        )
        == 0
    )


async def create_primary_user_with_linked_email() -> RecipeUserId:
    # The primary user's root login method has personal@example.com, and a linked login
    # method has work@example.com
    primary_recipe_user_id = await create_verified_primary_emailpassword_user(
        "personal@example.com"
    )
    sign_up_res = await sign_up(
        "public", "work@example.com", "password123", user_context={"do_not_link": True}
    )
    assert isinstance(sign_up_res, SignUpOkResult)
    linked_recipe_user_id = sign_up_res.user.login_methods[0].recipe_user_id
    await verify_email(linked_recipe_user_id, "work@example.com")
    link_res = await link_accounts(
        linked_recipe_user_id, primary_recipe_user_id.get_as_string()
    )
    assert link_res.status == "OK"
    return primary_recipe_user_id


async def test_recover_account_email_is_not_sent_for_an_email_that_is_not_the_root_login_methods_email():
    client = init_st_and_get_client()
    await create_primary_user_with_linked_email()

    body, _ = post(
        client, "/auth/user/webauthn/reset/token", {"email": "work@example.com"}
    )

    assert body["status"] == "OK"
    assert "work@example.com" not in recover_account_tokens


async def test_recover_account_works_through_the_root_login_methods_email():
    client = init_st_and_get_client()
    primary_recipe_user_id = await create_primary_user_with_linked_email()

    token = request_recover_account_token(client, "personal@example.com")
    register_options = get_register_options_for_token(client, token)
    res = recover_account(client, token, register_options, new_authenticator())

    assert res["status"] == "OK"
    primary_user = await get_user(primary_recipe_user_id.get_as_string())
    assert primary_user is not None
    assert any(lm.recipe_id == "webauthn" for lm in primary_user.login_methods)
