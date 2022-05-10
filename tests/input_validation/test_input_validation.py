import pytest
from typing import Dict, Any
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import emailpassword, emailverification, passwordless


@pytest.mark.asyncio
async def test_init_validation_emailpassword():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info='AppInfo',  # type: ignore
            framework='fastapi',
            recipe_list=[
                emailpassword.init(),
            ]
        )
    assert 'app_info must be an instance of InputAppInfo' == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='fastapi',
            recipe_list=[
                emailpassword.init(
                    sign_up_feature='sign up'  # type: ignore
                ),
            ]
        )
    assert 'sign_up_feature must be of type InputSignUpFeature or None' == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='fastapi',
            recipe_list=[
                emailpassword.init(
                    reset_password_using_token_feature='reset password'  # type: ignore
                ),
            ]
        )
    assert 'reset_password_using_token_feature must be of type InputResetPasswordUsingTokenFeature or None' == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='fastapi',
            recipe_list=[
                emailpassword.init(
                    email_verification_feature='email verify'  # type: ignore
                ),
            ]
        )
    assert 'email_verification_feature must be of type InputEmailVerificationConfig or None' == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='fastapi',
            recipe_list=[
                emailpassword.init(
                    override='override'  # type: ignore
                ),
            ]
        )
    assert 'override must be of type InputOverrideConfig or None' == str(ex.value)


async def get_email_for_user_id(user_id: str, user_context: Dict[str, Any]) -> str:
    print(user_context)
    return user_id


@pytest.mark.asyncio
async def test_init_validation_emailverification():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='fastapi',
            recipe_list=[
                emailverification.init('config')  # type: ignore
            ]
        )
    assert 'config must be an instance of ParentRecipeEmailVerificationConfig' == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='fastapi',
            recipe_list=[
                emailverification.init(
                    emailverification.ParentRecipeEmailVerificationConfig(
                        get_email_for_user_id=get_email_for_user_id,
                        override='override'))  # type: ignore
            ]
        )
    assert 'override must be of type OverrideConfig or None' == str(ex.value)


async def send_text_message(param: passwordless.CreateAndSendCustomTextMessageParameters, _: Dict[str, Any]):
    print(param)


@pytest.mark.asyncio
async def test_init_validation_passwordless():
    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info='AppInfo',  # type: ignore
            framework='fastapi',
            recipe_list=[
                passwordless.init(
                    flow_type="USER_INPUT_CODE",
                    contact_config=passwordless.ContactPhoneOnlyConfig(
                        create_and_send_custom_text_message=send_text_message
                    )
                )
            ]
        )
    assert 'app_info must be an instance of InputAppInfo' == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='fastapi',
            recipe_list=[
                passwordless.init(
                    flow_type="SOME_OTHER_CODE",  # type: ignore
                    contact_config=passwordless.ContactPhoneOnlyConfig(
                        create_and_send_custom_text_message=send_text_message
                    )
                )
            ]
        )
    assert 'flow_type must be one of USER_INPUT_CODE, MAGIC_LINK, USER_INPUT_CODE_AND_MAGIC_LINK' == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='fastapi',
            recipe_list=[
                passwordless.init(
                    flow_type="USER_INPUT_CODE",
                    contact_config='contact config'  # type: ignore
                )
            ]
        )
    assert 'contact_config must be of type ContactConfig' == str(ex.value)

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig('http://localhost:3567'),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://api.supertokens.io",
                website_domain="http://supertokens.io",
                api_base_path="/auth"
            ),
            framework='fastapi',
            recipe_list=[
                passwordless.init(
                    flow_type="USER_INPUT_CODE",
                    contact_config=passwordless.ContactPhoneOnlyConfig(
                        create_and_send_custom_text_message=send_text_message
                    ),
                    override='override'  # type: ignore
                )
            ]
        )
    assert 'override must be of type OverrideConfig' == str(ex.value)
