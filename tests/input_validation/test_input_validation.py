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
    usermetadata,
)
from supertokens_python.recipe.emailverification.interfaces import (
    GetEmailForUserIdOkResult,
)


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
    class CustomSMSDeliveryService(
        passwordless.SMSDeliveryInterface[passwordless.SMSTemplateVars]
    ):
        async def send_sms(
            self,
            template_vars: passwordless.SMSTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            pass

    class CustomEmailDeliveryService(
        passwordless.EmailDeliveryInterface[passwordless.EmailTemplateVars]
    ):
        async def send_email(
            self,
            template_vars: passwordless.EmailTemplateVars,
            user_context: Dict[str, Any],
        ) -> None:
            pass

    with pytest.raises(ValueError) as ex:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info="AppInfo",  # type: ignore
            framework="fastapi",
            recipe_list=[
                passwordless.init(
                    flow_type="USER_INPUT_CODE",
                    contact_config=passwordless.ContactPhoneOnlyConfig(),
                    email_delivery=passwordless.EmailDeliveryConfig(
                        CustomEmailDeliveryService()
                    ),
                    sms_delivery=passwordless.SMSDeliveryConfig(
                        CustomSMSDeliveryService()
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
                    contact_config=passwordless.ContactPhoneOnlyConfig(),
                    email_delivery=passwordless.EmailDeliveryConfig(
                        CustomEmailDeliveryService()
                    ),
                    sms_delivery=passwordless.SMSDeliveryConfig(
                        CustomSMSDeliveryService()
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
                    contact_config=passwordless.ContactPhoneOnlyConfig(),
                    email_delivery=passwordless.EmailDeliveryConfig(
                        CustomEmailDeliveryService()
                    ),
                    sms_delivery=passwordless.SMSDeliveryConfig(
                        CustomSMSDeliveryService()
                    ),
                    override="override",  # type: ignore
                )
            ],
        )
    assert "override must be of type OverrideConfig" == str(ex.value)


providers_list: List[thirdparty.ProviderInput] = [
    thirdparty.ProviderInput(
        config=thirdparty.ProviderConfig(
            third_party_id="google",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id=os.environ.get("GOOGLE_CLIENT_ID"),  # type: ignore
                    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),  # type: ignore
                )
            ],
        )
    ),
    thirdparty.ProviderInput(
        config=thirdparty.ProviderConfig(
            third_party_id="facebook",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id=os.environ.get("FACEBOOK_CLIENT_ID"),  # type: ignore
                    client_secret=os.environ.get("FACEBOOK_CLIENT_SECRET"),  # type: ignore
                )
            ],
        )
    ),
    thirdparty.ProviderInput(
        config=thirdparty.ProviderConfig(
            third_party_id="github",
            clients=[
                thirdparty.ProviderClientConfig(
                    client_id=os.environ.get("GITHUB_CLIENT_ID"),  # type: ignore
                    client_secret=os.environ.get("GITHUB_CLIENT_SECRET"),  # type: ignore
                )
            ],
        )
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
