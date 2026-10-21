from pytest import mark, raises
from supertokens_python import init
from supertokens_python.recipe import passwordless, session
from supertokens_python.recipe.passwordless.asyncio import (
    ConsumeCodeOkResult,
    ConsumeCodeRestartFlowError,
    CreateCodeOkResult,
    consume_code,
    create_code,
    list_codes_by_email,
    list_codes_by_phone_number,
    revoke_all_codes,
)

from tests.utils import get_new_core_app_url, get_st_init_args

pytestmark = mark.asyncio

EMAIL = "test@example.com"
PHONE_NUMBER = "+14155552671"


def init_st():
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                session.init(),
                passwordless.init(
                    contact_config=passwordless.ContactEmailOrPhoneConfig(),
                    flow_type="USER_INPUT_CODE",
                ),
            ],
        )
    )


async def consume(code: CreateCodeOkResult):
    return await consume_code(
        "public",
        code.pre_auth_session_id,
        user_input_code=code.user_input_code,
        device_id=code.device_id,
    )


async def test_revoke_all_codes_by_phone_number():
    init_st()
    phone_code = await create_code("public", phone_number=PHONE_NUMBER)
    email_code = await create_code("public", email=EMAIL)

    await revoke_all_codes("public", phone_number=PHONE_NUMBER)

    assert isinstance(await consume(phone_code), ConsumeCodeRestartFlowError)
    assert await list_codes_by_phone_number("public", PHONE_NUMBER) == []
    # Codes of other contact methods are not revoked
    assert isinstance(await consume(email_code), ConsumeCodeOkResult)


async def test_revoke_all_codes_by_email():
    init_st()
    email_code = await create_code("public", email=EMAIL)
    phone_code = await create_code("public", phone_number=PHONE_NUMBER)

    await revoke_all_codes("public", email=EMAIL)

    assert isinstance(await consume(email_code), ConsumeCodeRestartFlowError)
    assert await list_codes_by_email("public", EMAIL) == []
    # Codes of other contact methods are not revoked
    assert isinstance(await consume(phone_code), ConsumeCodeOkResult)


async def test_revoke_all_codes_with_both_email_and_phone_number_fails():
    init_st()
    email_code = await create_code("public", email=EMAIL)
    phone_code = await create_code("public", phone_number=PHONE_NUMBER)

    with raises(Exception, match="exactly one of email or phoneNumber"):
        await revoke_all_codes("public", email=EMAIL, phone_number=PHONE_NUMBER)

    assert len(await list_codes_by_email("public", EMAIL)) == 1
    assert len(await list_codes_by_phone_number("public", PHONE_NUMBER)) == 1
    assert isinstance(await consume(email_code), ConsumeCodeOkResult)
    assert isinstance(await consume(phone_code), ConsumeCodeOkResult)
