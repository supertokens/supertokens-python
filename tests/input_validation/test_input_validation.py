import pytest
from typing import Dict, Any
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import passwordless


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
