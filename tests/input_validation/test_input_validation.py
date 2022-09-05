import os
from typing import Any, Dict, List

import pytest
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import (
    emailpassword,
    emailverification,
    jwt,
    openid,
    passwordless,
    session,
    thirdparty,
    thirdpartyemailpassword,
    thirdpartypasswordless,
    usermetadata,
)
from supertokens_python.recipe.emailverification.interfaces import (
    GetEmailForUserIdOkResult,
)
from supertokens_python.recipe.passwordless.utils import ContactEmailOrPhoneConfig
from supertokens_python.recipe.thirdparty.provider import Provider


@pytest.mark.asyncio
async def test_init_validation_emailpassword():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info="AppInfo",  # type: ignore
            framework="fastapi",
            recipe_list=[
                emailpassword.init(),
            ],
        )
    assert "app_info must be an instance of InputAppInfo" == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                emailpassword.init(sign_up_feature="sign up"),  # type: ignore
            ],
        )
    assert "sign_up_feature must be of type InputSignUpFeature or None" == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                emailpassword.init(
                    reset_password_using_token_feature="reset password"  # type: ignore
                ),
            ],
        )
    assert (
        "reset_password_using_token_feature must be of type InputResetPasswordUsingTokenFeature or None"
        == str(ex.value)
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                emailverification.init("email verify"),  # type: ignore
                emailpassword.init(),
            ],
        )
    assert (
        "Email Verification recipe mode must be one of 'REQUIRED' or 'OPTIONAL'"
        == str(ex.value)
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                emailpassword.init(override="override"),  # type: ignore
            ],
        )
    assert "override must be of type InputOverrideConfig or None" == str(ex.value)


async def get_email_for_user_id(_: str, __: Dict[str, Any]):
    return GetEmailForUserIdOkResult("foo@example.com")


@pytest.mark.asyncio
async def test_init_validation_emailverification():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[emailverification.init("config")],  # type: ignore
        )
    assert (
        "Email Verification recipe mode must be one of 'REQUIRED' or 'OPTIONAL'"
        == str(ex.value)
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                emailverification.init(
                    mode="OPTIONAL",
                    get_email_for_user_id=get_email_for_user_id,
                    override="override",  # type: ignore
                )
            ],
        )
    assert "override must be of type OverrideConfig or None" == str(ex.value)


@pytest.mark.asyncio
async def test_init_validation_jwt():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[jwt.init(jwt_validity_seconds="100")],  # type: ignore
        )
    assert "jwt_validity_seconds must be an integer or None" == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[jwt.init(override="override")],  # type: ignore
        )
    assert "override must be an instance of OverrideConfig or None" == str(ex.value)


@pytest.mark.asyncio
async def test_init_validation_openid():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[openid.init(override="override")],  # type: ignore
        )
    assert "override must be an instance of InputOverrideConfig or None" == str(
        ex.value
    )


async def send_text_message(
    _: passwordless.CreateAndSendCustomTextMessageParameters, __: Dict[str, Any]
):
    pass


@pytest.mark.asyncio
async def test_init_validation_passwordless():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info="AppInfo",  # type: ignore
            framework="fastapi",
            recipe_list=[
                passwordless.init(
                    flow_type="USER_INPUT_CODE",
                    contact_config=passwordless.ContactPhoneOnlyConfig(
                        create_and_send_custom_text_message=send_text_message
                    ),
                )
            ],
        )
    assert "app_info must be an instance of InputAppInfo" == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                passwordless.init(
                    flow_type="SOME_OTHER_CODE",  # type: ignore
                    contact_config=passwordless.ContactPhoneOnlyConfig(
                        create_and_send_custom_text_message=send_text_message
                    ),
                )
            ],
        )
    assert (
        "flow_type must be one of USER_INPUT_CODE, MAGIC_LINK, USER_INPUT_CODE_AND_MAGIC_LINK"
        == str(ex.value)
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                passwordless.init(
                    flow_type="USER_INPUT_CODE",
                    contact_config="contact config",  # type: ignore
                )
            ],
        )
    assert "contact_config must be of type ContactConfig" == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                passwordless.init(
                    flow_type="USER_INPUT_CODE",
                    contact_config=passwordless.ContactPhoneOnlyConfig(
                        create_and_send_custom_text_message=send_text_message
                    ),
                    override="override",  # type: ignore
                )
            ],
        )
    assert "override must be of type OverrideConfig" == str(ex.value)


providers_list: List[Provider] = [
    thirdparty.Google(
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),  # type: ignore
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),  # type: ignore
    ),
    thirdparty.Facebook(
        client_id=os.environ.get("FACEBOOK_CLIENT_ID"),  # type: ignore
        client_secret=os.environ.get("FACEBOOK_CLIENT_SECRET"),  # type: ignore
    ),
    thirdparty.Github(
        client_id=os.environ.get("GITHUB_CLIENT_ID"),  # type: ignore
        client_secret=os.environ.get("GITHUB_CLIENT_SECRET"),  # type: ignore
    ),
]


@pytest.mark.asyncio
async def test_init_validation_session():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[session.init(anti_csrf="ABCDE")],  # type: ignore
        )
    assert "anti_csrf must be one of VIA_TOKEN, VIA_CUSTOM_HEADER, NONE or None" == str(
        ex.value
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[session.init(error_handlers="error handlers")],  # type: ignore
        )
    assert "error_handlers must be an instance of ErrorHandlers or None" == str(
        ex.value
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[session.init(override="override")],  # type: ignore
        )
    assert "override must be an instance of InputOverrideConfig or None" == str(
        ex.value
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[session.init(jwt="jwt")],  # type: ignore
        )
    assert "jwt must be an instance of JWTConfig or None" == str(ex.value)


@pytest.mark.asyncio
async def test_init_validation_thirdparty():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdparty.init(sign_in_and_up_feature="sign in up")  # type: ignore
            ],
        )
    assert "sign_in_and_up_feature must be an instance of SignInAndUpFeature" == str(
        ex.value
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdparty.init(
                    sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                        providers_list
                    ),
                    override="override",  # type: ignore
                )
            ],
        )
    assert "override must be an instance of InputOverrideConfig or None" == str(
        ex.value
    )


@pytest.mark.asyncio
async def test_init_validation_thirdpartyemailpassword():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdpartyemailpassword.init(sign_up_feature="sign up")  # type: ignore
            ],
        )
    assert "sign_up_feature must be of type InputSignUpFeature or None" == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdpartyemailpassword.init(
                    reset_password_using_token_feature="reset password"  # type: ignore
                )
            ],
        )
    assert (
        "reset_password_using_token_feature must be of type InputResetPasswordUsingTokenFeature or None"
        == str(ex.value)
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                emailverification.init("email verification"),  # type: ignore
                thirdpartyemailpassword.init(),
            ],
        )
    assert (
        "Email Verification recipe mode must be one of 'REQUIRED' or 'OPTIONAL'"
        == str(ex.value)
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdpartyemailpassword.init(override="override")  # type: ignore
            ],
        )
    assert "override must be of type InputOverrideConfig or None" == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdpartyemailpassword.init(providers="providers")  # type: ignore
            ],
        )
    assert "providers must be of type List[Provider] or None" == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdpartyemailpassword.init(providers=["providers"])  # type: ignore
            ],
        )
    assert "providers must be of type List[Provider] or None" == str(ex.value)


async def save_code_text(
    _param: passwordless.CreateAndSendCustomTextMessageParameters, _: Dict[str, Any]
):
    pass


async def save_code_email(
    _param: passwordless.CreateAndSendCustomEmailParameters, _: Dict[str, Any]
):
    pass


@pytest.mark.asyncio
async def test_init_validation_thirdpartypasswordless():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdpartypasswordless.init(
                    contact_config="contact config",  # type: ignore
                    flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                )
            ],
        )
    assert "contact_config must be an instance of ContactConfig" == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdpartypasswordless.init(
                    contact_config=ContactEmailOrPhoneConfig(
                        create_and_send_custom_text_message=save_code_text,
                        create_and_send_custom_email=save_code_email,
                    ),
                    flow_type="CUSTOM",  # type: ignore
                )
            ],
        )
    assert (
        "flow_type must be one of USER_INPUT_CODE, MAGIC_LINK, USER_INPUT_CODE_AND_MAGIC_LINK"
        == str(ex.value)
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                emailverification.init(
                    "email verify",  # type: ignore
                ),
                thirdpartypasswordless.init(
                    contact_config=ContactEmailOrPhoneConfig(
                        create_and_send_custom_text_message=save_code_text,
                        create_and_send_custom_email=save_code_email,
                    ),
                    flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                ),
            ],
        )
    assert (
        "Email Verification recipe mode must be one of 'REQUIRED' or 'OPTIONAL'"
        == str(ex.value)
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdpartypasswordless.init(
                    contact_config=ContactEmailOrPhoneConfig(
                        create_and_send_custom_text_message=save_code_text,
                        create_and_send_custom_email=save_code_email,
                    ),
                    flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                    override="override",  # type: ignore
                )
            ],
        )
    assert "override must be an instance of InputOverrideConfig or None" == str(
        ex.value
    )

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdpartypasswordless.init(
                    contact_config=ContactEmailOrPhoneConfig(
                        create_and_send_custom_text_message=save_code_text,
                        create_and_send_custom_email=save_code_email,
                    ),
                    flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                    providers="providers",  # type: ignore
                )
            ],
        )
    assert "providers must be of type List[Provider] or None" == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[
                thirdpartypasswordless.init(
                    contact_config=ContactEmailOrPhoneConfig(
                        create_and_send_custom_text_message=save_code_text,
                        create_and_send_custom_email=save_code_email,
                    ),
                    flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
                    providers=["providers"],  # type: ignore
                )
            ],
        )
    assert "providers must be of type List[Provider] or None" == str(ex.value)


@pytest.mark.asyncio
async def test_init_validation_usermetadata():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth",
            ),
            framework="fastapi",
            recipe_list=[usermetadata.init(override="override")],  # type: ignore
        )
    assert "override must be an instance of InputOverrideConfig or None" == str(
        ex.value
    )
