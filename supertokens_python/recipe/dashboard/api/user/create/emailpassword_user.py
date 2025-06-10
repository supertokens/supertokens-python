from typing import Any, Dict, Union

from supertokens_python.exceptions import BadInputError
from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import (
    EmailAlreadyExistsError,
    SignUpOkResult,
)
from supertokens_python.recipe.emailpassword.recipe import EmailPasswordRecipe
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.response import APIResponse


class CreateEmailPasswordUserOkResponse(APIResponse):
    def __init__(self, user: User, recipe_user_id: RecipeUserId):
        self.status = "OK"
        self.user = user
        self.recipe_user_id = recipe_user_id

    def to_json(self):
        return {
            "status": self.status,
            "user": self.user.to_json(),
            "recipeUserId": self.recipe_user_id.get_as_string(),
        }


class CreateEmailPasswordUserFeatureNotEnabledResponse(APIResponse):
    def __init__(self):
        self.status = "FEATURE_NOT_ENABLED_ERROR"

    def to_json(self):
        return {"status": self.status}


class CreateEmailPasswordUserEmailAlreadyExistsResponse(APIResponse):
    def __init__(self):
        self.status = "EMAIL_ALREADY_EXISTS_ERROR"

    def to_json(self):
        return {"status": self.status}


class CreateEmailPasswordUserEmailValidationErrorResponse(APIResponse):
    def __init__(self, message: str):
        self.status = "EMAIL_VALIDATION_ERROR"
        self.message = message

    def to_json(self):
        return {"status": self.status, "message": self.message}


class CreateEmailPasswordUserPasswordValidationErrorResponse(APIResponse):
    def __init__(self, message: str):
        self.status = "PASSWORD_VALIDATION_ERROR"
        self.message = message

    def to_json(self):
        return {"status": self.status, "message": self.message}


async def create_email_password_user(
    _: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    __: Dict[str, Any],
) -> Union[
    CreateEmailPasswordUserOkResponse,
    CreateEmailPasswordUserFeatureNotEnabledResponse,
    CreateEmailPasswordUserEmailAlreadyExistsResponse,
    CreateEmailPasswordUserEmailValidationErrorResponse,
    CreateEmailPasswordUserPasswordValidationErrorResponse,
]:
    email_password: EmailPasswordRecipe
    try:
        email_password = EmailPasswordRecipe.get_instance()
    except Exception:
        return CreateEmailPasswordUserFeatureNotEnabledResponse()

    request_body = await api_options.request.json()
    if request_body is None:
        raise BadInputError("Request body is missing")

    email = request_body.get("email")
    password = request_body.get("password")

    if not isinstance(email, str):
        raise BadInputError(
            "Required parameter 'email' is missing or has an invalid type"
        )

    if not isinstance(password, str):
        raise BadInputError(
            "Required parameter 'password' is missing or has an invalid type"
        )

    email_form_field = next(
        field
        for field in email_password.config.sign_up_feature.form_fields
        if field.id == "email"
    )
    validate_email_error = await email_form_field.validate(email, tenant_id)

    if validate_email_error is not None:
        return CreateEmailPasswordUserEmailValidationErrorResponse(validate_email_error)

    password_form_field = next(
        field
        for field in email_password.config.sign_up_feature.form_fields
        if field.id == "password"
    )
    validate_password_error = await password_form_field.validate(password, tenant_id)

    if validate_password_error is not None:
        return CreateEmailPasswordUserPasswordValidationErrorResponse(
            validate_password_error
        )

    response = await sign_up(tenant_id, email, password)

    if isinstance(response, SignUpOkResult):
        return CreateEmailPasswordUserOkResponse(response.user, response.recipe_user_id)
    elif isinstance(response, EmailAlreadyExistsError):
        return CreateEmailPasswordUserEmailAlreadyExistsResponse()
    else:
        raise Exception(
            "This should never happen: EmailPassword.sign_up threw a session user related error without passing a session"
        )
