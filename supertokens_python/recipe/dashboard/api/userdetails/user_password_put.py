from typing import Any, Callable, Dict, List, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.asyncio import (
    create_reset_password_token as ep_create_reset_password_token,
)
from supertokens_python.recipe.emailpassword.asyncio import (
    reset_password_using_token as ep_reset_password_using_token,
)
from supertokens_python.recipe.emailpassword.constants import FORM_FIELD_PASSWORD_ID
from supertokens_python.recipe.emailpassword.interfaces import (
    CreateResetPasswordOkResult,
    CreateResetPasswordWrongUserIdError,
    ResetPasswordUsingTokenInvalidTokenError,
    ResetPasswordUsingTokenOkResult,
)
from supertokens_python.recipe.emailpassword.types import NormalisedFormField
from supertokens_python.recipe.thirdpartyemailpassword import (
    ThirdPartyEmailPasswordRecipe,
)
from supertokens_python.recipe.thirdpartyemailpassword.asyncio import (
    create_reset_password_token as tpep_create_reset_password_token,
)
from supertokens_python.recipe.thirdpartyemailpassword.asyncio import (
    reset_password_using_token as tpep_reset_password_using_token,
)
from supertokens_python.utils import Awaitable
from typing_extensions import Literal

from ...interfaces import (
    APIInterface,
    APIOptions,
    UserPasswordPutAPIInvalidPasswordErrorResponse,
    UserPasswordPutAPIResponse,
)


async def handle_user_password_put(
    _api_interface: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[UserPasswordPutAPIResponse, UserPasswordPutAPIInvalidPasswordErrorResponse]:
    request_body: Dict[str, Any] = await api_options.request.json()  # type: ignore
    user_id = request_body.get("userId")
    new_password = request_body.get("newPassword")

    if user_id is None or not isinstance(user_id, str):
        raise_bad_input_exception("Missing required parameter 'userId'")

    if new_password is None or not isinstance(new_password, str):
        raise_bad_input_exception("Missing required parameter 'newPassword'")

    recipe_to_use: Union[
        Literal["emailpassword", "thirdpartyemailpassword"], None
    ] = None

    try:
        EmailPasswordRecipe.get_instance()
        recipe_to_use = "emailpassword"
    except Exception:
        pass

    if recipe_to_use is None:
        try:
            ThirdPartyEmailPasswordRecipe.get_instance()
            recipe_to_use = "thirdpartyemailpassword"
        except Exception:
            pass

    if recipe_to_use is None:
        raise Exception("Should not come here")

    async def reset_password(
        form_fields: List[NormalisedFormField],
        create_reset_password_token: Callable[
            [str, str, Dict[str, Any]],
            Awaitable[
                Union[CreateResetPasswordOkResult, CreateResetPasswordWrongUserIdError]
            ],
        ],
        reset_password_using_token: Callable[
            [str, str, str, Dict[str, Any]],
            Awaitable[
                Union[
                    ResetPasswordUsingTokenOkResult,
                    ResetPasswordUsingTokenInvalidTokenError,
                ]
            ],
        ],
    ) -> Union[
        UserPasswordPutAPIResponse, UserPasswordPutAPIInvalidPasswordErrorResponse
    ]:
        password_form_field = [
            field for field in form_fields if field.id == FORM_FIELD_PASSWORD_ID
        ][0]

        password_validation_error = await password_form_field.validate(
            new_password, tenant_id
        )

        if password_validation_error is not None:
            return UserPasswordPutAPIInvalidPasswordErrorResponse(
                password_validation_error
            )

        password_reset_token = await create_reset_password_token(
            tenant_id, user_id, user_context
        )

        if isinstance(password_reset_token, CreateResetPasswordWrongUserIdError):
            # Techincally it can but its an edge case so we assume that it wont
            # UNKNOWN_USER_ID_ERROR
            raise Exception("Should never come here")

        password_reset_response = await reset_password_using_token(
            tenant_id, password_reset_token.token, new_password, user_context
        )

        if isinstance(
            password_reset_response, ResetPasswordUsingTokenInvalidTokenError
        ):
            # RESET_PASSWORD_INVALID_TOKEN_ERROR
            raise Exception("Should not come here")

        return UserPasswordPutAPIResponse()

    if recipe_to_use == "emailpassword":
        return await reset_password(
            EmailPasswordRecipe.get_instance().config.sign_up_feature.form_fields,
            ep_create_reset_password_token,
            ep_reset_password_using_token,
        )

    if recipe_to_use == "thirdpartyemailpassword":
        return await reset_password(
            ThirdPartyEmailPasswordRecipe.get_instance().email_password_recipe.config.sign_up_feature.form_fields,
            tpep_create_reset_password_token,
            tpep_reset_password_using_token,
        )
