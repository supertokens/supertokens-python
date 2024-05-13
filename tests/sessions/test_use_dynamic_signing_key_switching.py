import pytest
from supertokens_python import init
from supertokens_python.recipe import session
from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
    get_session_without_request_response,
    refresh_session_without_request_response,
)
from supertokens_python.recipe.session.session_class import SessionContainer
from tests.utils import (
    get_st_init_args,
    setup_function,
    start_st,
    teardown_function,
    reset,
)
from supertokens_python.recipe.session.jwt import (
    parse_jwt_without_signature_verification,
)
from supertokens_python.recipe.session.interfaces import GetSessionTokensDangerouslyDict

_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore

pytestmark = pytest.mark.asyncio


async def test_dynamic_key_switching():
    init(**get_st_init_args([session.init(use_dynamic_access_token_signing_key=True)]))
    start_st()

    # Create a new session without an actual HTTP request-response flow
    create_res: SessionContainer = await create_new_session_without_request_response(
        "public", "test-user-id", {"tokenProp": True}, {"dbProp": True}
    )

    # Extract session tokens for further testing
    tokens = create_res.get_all_session_tokens_dangerously()
    check_access_token_signing_key_type(tokens, True)

    # Reset and reinitialize with dynamic signing key disabled
    reset(stop_core=False)
    init(**get_st_init_args([session.init(use_dynamic_access_token_signing_key=False)]))

    caught_exception = None
    try:
        # Attempt to retrieve the session using previously obtained tokens
        await get_session_without_request_response(
            tokens["accessToken"], tokens["antiCsrfToken"]
        )
    except Exception as e:
        caught_exception = e

    # Check for the expected exception due to token signing key mismatch
    assert (
        caught_exception is not None
    ), "Expected an exception to be thrown, but none was."
    assert (
        str(caught_exception)
        == "The access token doesn't match the use_dynamic_access_token_signing_key setting"
    ), f"Unexpected exception message: {str(caught_exception)}"


async def test_refresh_session():
    init(**get_st_init_args([session.init(use_dynamic_access_token_signing_key=True)]))
    start_st()

    # Create a new session without an actual HTTP request-response flow
    create_res: SessionContainer = await create_new_session_without_request_response(
        "public", "test-user-id", {"tokenProp": True}, {"dbProp": True}
    )

    # Extract session tokens for further testing
    tokens = create_res.get_all_session_tokens_dangerously()
    check_access_token_signing_key_type(tokens, True)

    # Reset and reinitialize with dynamic signing key disabled
    reset(stop_core=False)
    init(**get_st_init_args([session.init(use_dynamic_access_token_signing_key=False)]))

    assert tokens["refreshToken"] is not None

    # Refresh session
    refreshed_session = await refresh_session_without_request_response(
        tokens["refreshToken"], True, tokens["antiCsrfToken"]
    )
    tokens_after_refresh = refreshed_session.get_all_session_tokens_dangerously()
    assert tokens_after_refresh["accessAndFrontTokenUpdated"] is True
    check_access_token_signing_key_type(tokens_after_refresh, False)

    # Verify session after refresh
    verified_session = await get_session_without_request_response(
        tokens_after_refresh["accessToken"], tokens_after_refresh["antiCsrfToken"]
    )
    assert verified_session is not None
    tokens_after_verify = verified_session.get_all_session_tokens_dangerously()
    assert tokens_after_verify["accessAndFrontTokenUpdated"] is True
    check_access_token_signing_key_type(tokens_after_verify, False)

    # Verify session again
    verified2_session = await get_session_without_request_response(
        tokens_after_verify["accessToken"], tokens_after_verify["antiCsrfToken"]
    )
    assert verified2_session is not None
    tokens_after_verify2 = verified2_session.get_all_session_tokens_dangerously()
    assert tokens_after_verify2["accessAndFrontTokenUpdated"] is False


def check_access_token_signing_key_type(
    tokens: GetSessionTokensDangerouslyDict, is_dynamic: bool
):
    info = parse_jwt_without_signature_verification(tokens["accessToken"])
    if is_dynamic:
        assert info.kid is not None and info.kid.startswith("d-")
    else:
        assert info.kid is not None and info.kid.startswith("s-")
