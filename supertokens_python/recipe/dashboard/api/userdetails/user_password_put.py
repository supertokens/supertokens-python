from typing import Any, Dict, List, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.constants import FORM_FIELD_PASSWORD_ID
from supertokens_python.recipe.emailpassword.interfaces import (
    UnknownUserIdError,
    PasswordResetTokenInvalidError,
)
from supertokens_python.recipe.emailpassword.asyncio import (
    create_reset_password_token,
    reset_password_using_token,
)
from supertokens_python.recipe.emailpassword.types import NormalisedFormField

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

    async def reset_password(
        form_fields: List[NormalisedFormField],
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
            tenant_id, user_id, "", user_context
        )

        if isinstance(password_reset_token, UnknownUserIdError):
            # Techincally it can but its an edge case so we assume that it wont
            # UNKNOWN_USER_ID_ERROR
            raise Exception("Should never come here")

        password_reset_response = await reset_password_using_token(
            tenant_id, password_reset_token.token, new_password, user_context
        )

        if isinstance(password_reset_response, PasswordResetTokenInvalidError):
            # RESET_PASSWORD_INVALID_TOKEN_ERROR
            raise Exception("Should not come here")

        return UserPasswordPutAPIResponse()

    return await reset_password(
        EmailPasswordRecipe.get_instance().config.sign_up_feature.form_fields,
    )
