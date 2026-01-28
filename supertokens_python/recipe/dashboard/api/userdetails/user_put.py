from typing import Any, Dict, Union

from typing_extensions import Literal

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.dashboard.utils import (
    get_user_for_recipe_id,
)
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.asyncio import (
    update_email_or_password as ep_update_email_or_password,
)
from supertokens_python.recipe.emailpassword.constants import FORM_FIELD_EMAIL_ID
from supertokens_python.recipe.emailpassword.interfaces import (
    EmailAlreadyExistsError,
    UpdateEmailOrPasswordEmailChangeNotAllowedError,
)
from supertokens_python.recipe.passwordless import (
    ContactEmailOnlyConfig,
    ContactEmailOrPhoneConfig,
    ContactPhoneOnlyConfig,
    PasswordlessRecipe,
)
from supertokens_python.recipe.passwordless.asyncio import (
    update_user as pless_update_user,
)
from supertokens_python.recipe.passwordless.interfaces import (
    EmailChangeNotAllowedError,
    PhoneNumberChangeNotAllowedError,
    UpdateUserEmailAlreadyExistsError,
    UpdateUserPhoneNumberAlreadyExistsError,
    UpdateUserUnknownUserIdError,
)
from supertokens_python.recipe.passwordless.utils import (
    default_validate_email,
    default_validate_phone_number,
)
from supertokens_python.recipe.usermetadata import UserMetadataRecipe
from supertokens_python.recipe.usermetadata.asyncio import update_user_metadata
from supertokens_python.recipe.webauthn.functions import update_user_email
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    UnknownUserIdErrorResponse,
)
from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe
from supertokens_python.types import RecipeUserId

from .....types.response import APIResponse
from ...interfaces import (
    APIInterface,
    APIOptions,
)


class OkResponse(APIResponse):
    status: Literal["OK"]

    def __init__(self):
        self.status = "OK"

    def to_json(self):
        return {"status": self.status}


class EmailAlreadyExistsErrorResponse(APIResponse):
    status: Literal["EMAIL_ALREADY_EXISTS_ERROR"]

    def __init__(self):
        self.status = "EMAIL_ALREADY_EXISTS_ERROR"

    def to_json(self):
        return {"status": self.status}


class InvalidEmailErrorResponse(APIResponse):
    status: Literal["INVALID_EMAIL_ERROR"]
    error: str

    def __init__(self, error: str):
        self.status = "INVALID_EMAIL_ERROR"
        self.error = error

    def to_json(self):
        return {"status": self.status, "error": self.error}


class PhoneAlreadyExistsErrorResponse(APIResponse):
    status: Literal["PHONE_ALREADY_EXISTS_ERROR"]

    def __init__(self):
        self.status = "PHONE_ALREADY_EXISTS_ERROR"

    def to_json(self):
        return {"status": self.status}


class InvalidPhoneErrorResponse(APIResponse):
    status: Literal["INVALID_PHONE_ERROR"]
    error: str

    def __init__(self, error: str):
        self.status = "INVALID_PHONE_ERROR"
        self.error = error

    def to_json(self):
        return {"status": self.status, "error": self.error}


class EmailChangeNotAllowedErrorResponse(APIResponse):
    status: Literal["EMAIL_CHANGE_NOT_ALLOWED_ERROR"]
    error: str

    def __init__(self, error: str):
        self.status = "EMAIL_CHANGE_NOT_ALLOWED_ERROR"
        self.error = error

    def to_json(self):
        return {"status": self.status, "error": self.error}


class PhoneNumberChangeNotAllowedErrorResponse(APIResponse):
    status: Literal["PHONE_NUMBER_CHANGE_NOT_ALLOWED_ERROR"]
    error: str

    def __init__(self, error: str):
        self.status = "PHONE_NUMBER_CHANGE_NOT_ALLOWED_ERROR"
        self.error = error

    def to_json(self):
        return {"status": self.status, "error": self.error}


async def update_email_for_recipe_id(
    recipe_id: str,
    recipe_user_id: RecipeUserId,
    email: str,
    tenant_id: str,
    user_context: Dict[str, Any],
) -> Union[
    OkResponse,
    InvalidEmailErrorResponse,
    EmailAlreadyExistsErrorResponse,
    EmailChangeNotAllowedErrorResponse,
]:
    if recipe_id == "emailpassword":
        email_form_fields = [
            field
            for field in EmailPasswordRecipe.get_instance().config.sign_up_feature.form_fields
            if field.id == FORM_FIELD_EMAIL_ID
        ]

        validation_error = await email_form_fields[0].validate(email, tenant_id)

        if validation_error is not None:
            return InvalidEmailErrorResponse(validation_error)

        email_update_response = await ep_update_email_or_password(
            recipe_user_id, email=email, user_context=user_context
        )

        if isinstance(email_update_response, EmailAlreadyExistsError):
            return EmailAlreadyExistsErrorResponse()
        elif isinstance(
            email_update_response, UpdateEmailOrPasswordEmailChangeNotAllowedError
        ):
            return EmailChangeNotAllowedErrorResponse(email_update_response.reason)

        return OkResponse()

    if recipe_id == "passwordless":
        passwordless_config = PasswordlessRecipe.get_instance().config

        if isinstance(passwordless_config.contact_config, ContactPhoneOnlyConfig):
            validation_error = await default_validate_email(email, tenant_id)
        else:
            if isinstance(
                passwordless_config.contact_config,
                (ContactEmailOnlyConfig, ContactEmailOrPhoneConfig),
            ):
                validation_error = (
                    await passwordless_config.contact_config.validate_email_address(
                        email, tenant_id
                    )
                )
            else:
                raise Exception("Should never come here")

        if validation_error is not None:
            return InvalidEmailErrorResponse(validation_error)

        update_result = await pless_update_user(
            recipe_user_id, email=email, user_context=user_context
        )

        if isinstance(update_result, UpdateUserUnknownUserIdError):
            raise Exception("Should never come here")
        elif isinstance(update_result, UpdateUserEmailAlreadyExistsError):
            return EmailAlreadyExistsErrorResponse()
        elif isinstance(
            update_result,
            (
                EmailChangeNotAllowedError,
                PhoneNumberChangeNotAllowedError,
            ),
        ):
            return EmailChangeNotAllowedErrorResponse(update_result.reason)

        return OkResponse()

    if recipe_id == "webauthn":
        validation_error = (
            await WebauthnRecipe.get_instance().config.validate_email_address(
                email=email,
                tenant_id=tenant_id,
                user_context=user_context,
            )
        )

        if validation_error is not None:
            return InvalidEmailErrorResponse(validation_error)

        email_update_response = await update_user_email(
            email=email,
            recipe_user_id=recipe_user_id.get_as_string(),
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if isinstance(email_update_response, EmailAlreadyExistsError):
            return EmailAlreadyExistsErrorResponse()

        if isinstance(email_update_response, UnknownUserIdErrorResponse):
            raise Exception("Should never come here")

    # If it comes here then the user is a third party user in which case the UI should not have allowed this
    raise Exception("Should never come here")


async def update_phone_for_recipe_id(
    recipe_user_id: RecipeUserId,
    phone: str,
    tenant_id: str,
    user_context: Dict[str, Any],
) -> Union[
    OkResponse,
    InvalidPhoneErrorResponse,
    PhoneAlreadyExistsErrorResponse,
    PhoneNumberChangeNotAllowedErrorResponse,
]:
    passwordless_config = PasswordlessRecipe.get_instance().config

    if isinstance(passwordless_config.contact_config, ContactEmailOnlyConfig):
        validation_error = await default_validate_phone_number(phone, tenant_id)
    elif isinstance(
        passwordless_config.contact_config,
        (ContactPhoneOnlyConfig, ContactEmailOrPhoneConfig),
    ):
        validation_error = (
            await passwordless_config.contact_config.validate_phone_number(
                phone, tenant_id
            )
        )
    else:
        raise Exception("Invalid contact config")

    if validation_error is not None:
        return InvalidPhoneErrorResponse(validation_error)

    update_result = await pless_update_user(
        recipe_user_id, phone_number=phone, user_context=user_context
    )

    if isinstance(update_result, UpdateUserUnknownUserIdError):
        raise Exception("Should never come here")
    elif isinstance(update_result, UpdateUserPhoneNumberAlreadyExistsError):
        return PhoneAlreadyExistsErrorResponse()
    elif isinstance(update_result, PhoneNumberChangeNotAllowedError):
        return PhoneNumberChangeNotAllowedErrorResponse(update_result.reason)

    return OkResponse()


async def handle_user_put(
    _api_interface: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[
    OkResponse,
    InvalidEmailErrorResponse,
    EmailAlreadyExistsErrorResponse,
    InvalidPhoneErrorResponse,
    PhoneAlreadyExistsErrorResponse,
    EmailChangeNotAllowedErrorResponse,
    PhoneNumberChangeNotAllowedErrorResponse,
]:
    request_body = await api_options.request.json()
    if request_body is None:
        raise_bad_input_exception("Request body is missing")
    recipe_user_id = request_body.get("recipeUserId")
    recipe_id = request_body.get("recipeId")
    first_name = request_body.get("firstName")
    last_name = request_body.get("lastName")
    email = request_body.get("email")
    phone = request_body.get("phone")

    if not isinstance(recipe_user_id, str):
        raise_bad_input_exception(
            "Required parameter 'recipeUserId' is missing or has an invalid type"
        )

    if not isinstance(recipe_id, str):
        raise_bad_input_exception(
            "Required parameter 'recipeId' is missing or has an invalid type"
        )

    if not isinstance(first_name, str):
        raise_bad_input_exception(
            "Required parameter 'firstName' is missing or has an invalid type"
        )

    if not isinstance(last_name, str):
        raise_bad_input_exception(
            "Required parameter 'lastName' is missing or has an invalid type"
        )

    if not isinstance(email, str):
        raise_bad_input_exception(
            "Required parameter 'email' is missing or has an invalid type"
        )

    if not isinstance(phone, str):
        raise_bad_input_exception(
            "Required parameter 'phone' is missing or has an invalid type"
        )

    user_response = await get_user_for_recipe_id(
        RecipeUserId(recipe_user_id), recipe_id, user_context
    )

    if user_response.user is None or user_response.recipe is None:
        raise Exception("Should never come here")

    if first_name.strip() or last_name.strip():
        is_recipe_initialized = False
        try:
            UserMetadataRecipe.get_instance()
            is_recipe_initialized = True
        except Exception:
            pass

        if is_recipe_initialized:
            metadata_update: Dict[str, Any] = {}

            if first_name.strip():
                metadata_update["first_name"] = first_name.strip()

            if last_name.strip():
                metadata_update["last_name"] = last_name.strip()

            await update_user_metadata(
                user_response.user.user.id, metadata_update, user_context
            )

    if email.strip():
        email_update_response = await update_email_for_recipe_id(
            user_response.recipe,
            RecipeUserId(recipe_user_id),
            email.strip(),
            tenant_id,
            user_context,
        )

        if isinstance(email_update_response, EmailChangeNotAllowedErrorResponse):
            return EmailChangeNotAllowedErrorResponse(email_update_response.error)

        if not isinstance(email_update_response, OkResponse):
            return email_update_response

    if phone.strip():
        phone_update_response = await update_phone_for_recipe_id(
            RecipeUserId(recipe_user_id),
            phone.strip(),
            tenant_id,
            user_context,
        )

        if isinstance(phone_update_response, PhoneNumberChangeNotAllowedErrorResponse):
            return PhoneNumberChangeNotAllowedErrorResponse(phone_update_response.error)

        if not isinstance(phone_update_response, OkResponse):
            return phone_update_response

    return OkResponse()
