"""
Regression tests for https://github.com/supertokens/supertokens-core/issues/1195

sign_in_post used to verify the same assertion twice against the core
(verify_credentials at the top, then sign_in -> verify_credentials again). The
core persists the signature counter on every verification, so the second call
presented a non-increasing signCount and webauthn4j rejected it as a cloned
authenticator ("Malicious counter value is detected..."), which sign_in_post
masked as INVALID_CREDENTIALS_ERROR.

This only triggered for authenticators that actually increment signCount
(Windows Hello, security keys, Chrome virtual authenticators). Apple and Google
passkeys keep signCount at 0 forever, which skips the check and hid the bug —
hence the zero-counter control test below.
"""

import random
from typing import Any, Dict

from fastapi import FastAPI
from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session, webauthn
from supertokens_python.recipe.webauthn import WebauthnConfig
from supertokens_python.recipe.webauthn.interfaces.recipe import AuthenticationPayload
from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe
from supertokens_python.types.base import UserContext
from tests.testclient import TestClientWithNoCookieJar as TestClient
from tests.utils import get_new_core_app_url
from tests.webauthn.soft_authenticator import SoftAuthenticator

# Must be a consistent pair: the core validates that the origin host ends with
# the relying party id. (The defaults derived from app_info — rpId = apiDomain
# host, origin = websiteDomain — do NOT satisfy this, so we set them explicitly.)
RP_ID = "supertokens.io"
ORIGIN = "https://supertokens.io"


async def _get_origin(**_: Any) -> str:
    return ORIGIN


@fixture(scope="function")
def client() -> TestClient:
    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens",
            api_domain="api.supertokens.io",
            website_domain="supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        mode="asgi",
        recipe_list=[
            webauthn.init(
                WebauthnConfig(get_relying_party_id=RP_ID, get_origin=_get_origin)
            ),
            session.init(),
        ],
    )

    app = FastAPI()
    app.add_middleware(get_middleware())
    return TestClient(app)


def _post(client: TestClient, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    response = client.post(path, json=body)
    assert response.status_code == 200, f"{path} -> {response.status_code}: {response.text[:400]}"
    return response.json()


def _register_user(
    client: TestClient, authenticator: SoftAuthenticator, *, sign_count: int
) -> str:
    """Registers a fresh user+passkey whose stored counter starts at `sign_count`;
    returns the webauthn user handle."""
    email = f"{random.random()}@supertokens.com".replace("0.", "")

    register_options = _post(client, "/auth/webauthn/options/register", {"email": email})
    assert register_options["status"] == "OK", register_options

    sign_up_response = _post(
        client,
        "/auth/webauthn/signup",
        {
            "credential": authenticator.create_attestation(
                register_options, sign_count=sign_count
            ),
            "webauthnGeneratedOptionsId": register_options["webauthnGeneratedOptionsId"],
            "shouldTryLinkingWithSessionUser": False,
        },
    )
    assert sign_up_response["status"] == "OK", sign_up_response

    return register_options["user"]["id"]


@mark.asyncio
async def test_api_sign_in_succeeds_with_counter_incrementing_authenticator(
    client: TestClient,
):
    """
    THE REGRESSION TEST for core#1195: a single, legitimate sign-in API call
    with an authenticator that increments its signature counter must succeed.
    On the unfixed SDK the second internal verification saw the already
    persisted counter and this returned INVALID_CREDENTIALS_ERROR.
    """
    authenticator = SoftAuthenticator(rp_id=RP_ID, origin=ORIGIN)
    user_handle = _register_user(client, authenticator, sign_count=1)

    signin_options = _post(client, "/auth/webauthn/options/signin", {})
    assert signin_options["status"] == "OK", signin_options

    sign_in_response = _post(
        client,
        "/auth/webauthn/signin",
        {
            "credential": authenticator.create_assertion(
                signin_options, sign_count=2, user_handle=user_handle
            ),
            "webauthnGeneratedOptionsId": signin_options["webauthnGeneratedOptionsId"],
            "shouldTryLinkingWithSessionUser": False,
        },
    )

    assert sign_in_response["status"] == "OK", (
        "A single sign-in with an incrementing signCount must succeed. Failure "
        "here means sign_in_post verified the assertion against the core more "
        "than once and tripped its own clone detection (supertokens-core#1195). "
        f"Got: {sign_in_response}"
    )


@mark.asyncio
async def test_direct_recipe_sign_in_succeeds_with_counter_incrementing_authenticator(
    client: TestClient,
):
    """
    Control: the same credential/assertion accepted via the recipe function,
    which verifies exactly once. Proves the assertion and counter handling are
    valid, isolating any API-layer double verification as the failure cause.
    """
    authenticator = SoftAuthenticator(rp_id=RP_ID, origin=ORIGIN)
    user_handle = _register_user(client, authenticator, sign_count=1)

    signin_options = _post(client, "/auth/webauthn/options/signin", {})
    assert signin_options["status"] == "OK", signin_options

    recipe = WebauthnRecipe.get_instance()
    user_context: UserContext = {}
    sign_in_result = await recipe.recipe_implementation.sign_in(
        webauthn_generated_options_id=signin_options["webauthnGeneratedOptionsId"],
        credential=AuthenticationPayload.model_validate(
            authenticator.create_assertion(
                signin_options, sign_count=2, user_handle=user_handle
            )
        ),
        tenant_id="public",
        session=None,
        should_try_linking_with_session_user=False,
        user_context=user_context,
    )

    assert sign_in_result.status == "OK", f"Got: {sign_in_result}"


@mark.asyncio
async def test_api_sign_in_succeeds_when_sign_count_stays_zero(client: TestClient):
    """
    Control: with signCount pinned to 0 (Apple/Google passkey behavior) the
    spec skips the counter check entirely, so a double verification would go
    unnoticed. This is why the bug was invisible in most manual testing.
    """
    authenticator = SoftAuthenticator(rp_id=RP_ID, origin=ORIGIN)
    user_handle = _register_user(client, authenticator, sign_count=0)

    signin_options = _post(client, "/auth/webauthn/options/signin", {})
    assert signin_options["status"] == "OK", signin_options

    sign_in_response = _post(
        client,
        "/auth/webauthn/signin",
        {
            "credential": authenticator.create_assertion(
                signin_options, sign_count=0, user_handle=user_handle
            ),
            "webauthnGeneratedOptionsId": signin_options["webauthnGeneratedOptionsId"],
            "shouldTryLinkingWithSessionUser": False,
        },
    )

    assert sign_in_response["status"] == "OK", f"Got: {sign_in_response}"
