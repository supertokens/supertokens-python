from typing import Any, Optional

from pytest import fixture, mark
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import webauthn
from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe
from tests.utils import get_new_core_app_url, outputs, reset


@fixture(scope="function")
def default_webauthn_recipe():
    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens",
            api_domain="api.supertokens.io",
            website_domain="supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            webauthn.init(),
        ],
    )

    webauthn_recipe = WebauthnRecipe.get_instance()
    assert webauthn_recipe.config is not None

    yield webauthn_recipe

    reset()


@mark.asyncio
async def test_default_config_get_origin(default_webauthn_recipe: WebauthnRecipe):
    webauthn_recipe = default_webauthn_recipe

    origin = await webauthn_recipe.config.get_origin(
        tenant_id="public", request=None, user_context={}
    )
    assert origin == "https://supertokens.io"


@mark.asyncio
async def test_default_config_get_relying_party_id(
    default_webauthn_recipe: WebauthnRecipe,
):
    webauthn_recipe = default_webauthn_recipe

    relying_party_id = await webauthn_recipe.config.get_relying_party_id(
        tenant_id="public", request=None, user_context={}
    )
    assert relying_party_id == "api.supertokens.io"


@mark.asyncio
async def test_default_config_get_relying_party_name(
    default_webauthn_recipe: WebauthnRecipe,
):
    webauthn_recipe = default_webauthn_recipe

    relying_party_name = await webauthn_recipe.config.get_relying_party_name(
        tenant_id="public", request=None, user_context={}
    )
    assert relying_party_name == "SuperTokens"


@mark.asyncio
@mark.parametrize(
    ("email", "expectation"),
    [
        ("aaaaa", outputs("Email is not valid")),
        ("aaaaa@aaaaa", outputs("Email is not valid")),
        ("random  User   @randomMail.com", outputs("Email is not valid")),
        ("*@*", outputs("Email is not valid")),
        ("validemail@gmail.com", outputs(None)),
    ],
)
async def test_default_config_validate_email(
    default_webauthn_recipe: WebauthnRecipe, email: str, expectation: Any
):
    webauthn_recipe = default_webauthn_recipe

    with expectation as output:
        assert (
            await webauthn_recipe.config.validate_email_address(
                email=email, tenant_id="public", user_context={}
            )
            == output
        )


@fixture(scope="function")
def custom_webauthn_recipe():
    async def get_origin(**kwargs: Any) -> str:
        return "testOrigin"

    async def get_relying_party_id(**kwargs: Any) -> str:
        return "testId"

    async def get_relying_party_name(**kwargs: Any) -> str:
        return "testName"

    async def validate_email_address(**kwargs: Any) -> Optional[str]:
        print("validate_email_address", f"{kwargs=}")

        if kwargs["email"] == "test":
            return "valid"

        return "invalid"

    init(
        supertokens_config=SupertokensConfig(get_new_core_app_url()),
        app_info=InputAppInfo(
            app_name="SuperTokens",
            api_domain="api.supertokens.io",
            website_domain="supertokens.io",
            api_base_path="/auth",
        ),
        framework="fastapi",
        recipe_list=[
            webauthn.init(
                config=webauthn.WebauthnConfig(
                    get_origin=get_origin,
                    get_relying_party_id=get_relying_party_id,
                    get_relying_party_name=get_relying_party_name,
                    validate_email_address=validate_email_address,
                ),
            ),
        ],
    )

    webauthn_recipe = WebauthnRecipe.get_instance()
    assert webauthn_recipe.config is not None

    yield webauthn_recipe

    reset()


@mark.asyncio
async def test_custom_config_get_origin(custom_webauthn_recipe: WebauthnRecipe):
    webauthn_recipe = custom_webauthn_recipe

    origin = await webauthn_recipe.config.get_origin(
        tenant_id="public", request=None, user_context={}
    )
    assert origin == "testOrigin"


@mark.asyncio
async def test_custom_config_get_relying_party_id(
    custom_webauthn_recipe: WebauthnRecipe,
):
    webauthn_recipe = custom_webauthn_recipe

    relying_party_id = await webauthn_recipe.config.get_relying_party_id(
        tenant_id="public", request=None, user_context={}
    )
    assert relying_party_id == "testId"


@mark.asyncio
async def test_custom_config_get_relying_party_name(
    custom_webauthn_recipe: WebauthnRecipe,
):
    webauthn_recipe = custom_webauthn_recipe

    relying_party_name = await webauthn_recipe.config.get_relying_party_name(
        tenant_id="public", request=None, user_context={}
    )
    assert relying_party_name == "testName"


@mark.asyncio
@mark.parametrize(
    ("email", "expectation"),
    [
        ("test", outputs("valid")),
        ("test!", outputs("invalid")),
    ],
)
async def test_custom_config_validate_email(
    custom_webauthn_recipe: WebauthnRecipe, email: str, expectation: Any
):
    webauthn_recipe = custom_webauthn_recipe

    with expectation as output:
        assert (
            await webauthn_recipe.config.validate_email_address(
                email=email, tenant_id="public", user_context={}
            )
            == output
        )
