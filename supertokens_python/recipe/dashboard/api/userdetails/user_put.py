from typing import Any, Dict, Optional, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.dashboard.utils import (
    get_user_for_recipe_id,
    is_valid_recipe_id,
)
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.asyncio import (
    update_email_or_password as ep_update_email_or_password,
)
from supertokens_python.recipe.emailpassword.constants import FORM_FIELD_EMAIL_ID
from supertokens_python.recipe.emailpassword.interfaces import (
    UpdateEmailOrPasswordEmailAlreadyExistsError,
    UpdateEmailOrPasswordUnknownUserIdError,
)
from supertokens_python.recipe.passwordless import PasswordlessRecipe
from supertokens_python.recipe.passwordless.asyncio import (
    update_user as pless_update_user,
)
from supertokens_python.recipe.passwordless.interfaces import (
    UpdateUserEmailAlreadyExistsError as EmailAlreadyExistsErrorResponse,
)
from supertokens_python.recipe.passwordless.interfaces import (
    UpdateUserPhoneNumberAlreadyExistsError as PhoneNumberAlreadyExistsError,
)
from supertokens_python.recipe.passwordless.interfaces import (
    UpdateUserUnknownUserIdError as PlessUpdateUserUnknownUserIdError,
)
from supertokens_python.recipe.passwordless.utils import (
    ContactEmailOnlyConfig,
    ContactEmailOrPhoneConfig,
    ContactPhoneOnlyConfig,
    default_validate_email,
    default_validate_phone_number,
)
from supertokens_python.recipe.thirdpartyemailpassword import (
    ThirdPartyEmailPasswordRecipe,
)
from supertokens_python.recipe.thirdpartyemailpassword.asyncio import (
    update_email_or_password as tpep_update_email_or_password,
)
from supertokens_python.recipe.thirdpartypasswordless import (
    ThirdPartyPasswordlessRecipe,
)
from supertokens_python.recipe.usermetadata import UserMetadataRecipe
from supertokens_python.recipe.usermetadata.asyncio import update_user_metadata

from ...interfaces import (
    APIInterface,
    APIOptions,
    UserPutAPIEmailAlreadyExistsErrorResponse,
    UserPutAPIInvalidEmailErrorResponse,
    UserPutAPIInvalidPhoneErrorResponse,
    UserPutAPIOkResponse,
    UserPutPhoneAlreadyExistsAPIResponse,
)


async def update_email_for_recipe_id(
    recipe_id: str,
    user_id: str,
    email: str,
    tenant_id: str,
    user_context: Dict[str, Any],
) -> Union[
    UserPutAPIOkResponse,
    UserPutAPIInvalidEmailErrorResponse,
    UserPutAPIEmailAlreadyExistsErrorResponse,
]:
    validation_error: Optional[str] = None

    if recipe_id == "emailpassword":
        form_fields = (
            EmailPasswordRecipe.get_instance().config.sign_up_feature.form_fields
        )
        email_form_fields = [
            form_field
            for form_field in form_fields
            if form_field.id == FORM_FIELD_EMAIL_ID
        ]

        validation_error = await email_form_fields[0].validate(email, tenant_id)

        if validation_error is not None:
            return UserPutAPIInvalidEmailErrorResponse(validation_error)

        email_update_response = await ep_update_email_or_password(
            user_id, email, user_context=user_context
        )

        if isinstance(
            email_update_response, UpdateEmailOrPasswordEmailAlreadyExistsError
        ):
            return UserPutAPIEmailAlreadyExistsErrorResponse()

        return UserPutAPIOkResponse()

    if recipe_id == "thirdpartyemailpassword":
        form_fields = (
            ThirdPartyEmailPasswordRecipe.get_instance().email_password_recipe.config.sign_up_feature.form_fields
        )
        email_form_fields = [
            form_field
            for form_field in form_fields
            if form_field.id == FORM_FIELD_EMAIL_ID
        ]

        validation_error = await email_form_fields[0].validate(email, tenant_id)

        if validation_error is not None:
            return UserPutAPIInvalidEmailErrorResponse(validation_error)

        email_update_response = await tpep_update_email_or_password(
            user_id, email, user_context=user_context
        )

        if isinstance(
            email_update_response, UpdateEmailOrPasswordEmailAlreadyExistsError
        ):
            return UserPutAPIEmailAlreadyExistsErrorResponse()

        if isinstance(email_update_response, UpdateEmailOrPasswordUnknownUserIdError):
            raise Exception("Should never come here")

        return UserPutAPIOkResponse()

    if recipe_id == "passwordless":
        validation_error = None

        passwordless_config = PasswordlessRecipe.get_instance().config.contact_config

        if isinstance(passwordless_config.contact_method, ContactPhoneOnlyConfig):
            validation_error = await default_validate_email(email, tenant_id)

        elif isinstance(
            passwordless_config, (ContactEmailOnlyConfig, ContactEmailOrPhoneConfig)
        ):
            validation_error = await passwordless_config.validate_email_address(
                email, tenant_id
            )

        if validation_error is not None:
            return UserPutAPIInvalidEmailErrorResponse(validation_error)

        update_result = await pless_update_user(
            user_id, email, user_context=user_context
        )

        if isinstance(update_result, PlessUpdateUserUnknownUserIdError):
            raise Exception("Should never come here")

        if isinstance(update_result, EmailAlreadyExistsErrorResponse):
            return UserPutAPIEmailAlreadyExistsErrorResponse()

        return UserPutAPIOkResponse()

    if recipe_id == "thirdpartypasswordless":
        validation_error = None

        passwordless_config = (
            ThirdPartyPasswordlessRecipe.get_instance().passwordless_recipe.config.contact_config
        )

        if isinstance(passwordless_config, ContactPhoneOnlyConfig):
            validation_error = await default_validate_email(email, tenant_id)
        elif isinstance(
            passwordless_config, (ContactEmailOnlyConfig, ContactEmailOrPhoneConfig)
        ):
            validation_error = await passwordless_config.validate_email_address(
                email, tenant_id
            )

        if validation_error is not None:
            return UserPutAPIInvalidEmailErrorResponse(validation_error)

        update_result = await pless_update_user(
            user_id, email, user_context=user_context
        )

        if isinstance(update_result, PlessUpdateUserUnknownUserIdError):
            raise Exception("Should never come here")

        if isinstance(update_result, EmailAlreadyExistsErrorResponse):
            return UserPutAPIEmailAlreadyExistsErrorResponse()

        return UserPutAPIOkResponse()

    # If it comes here then the user is a third party user in which case the UI should not have allowed this
    raise Exception("Should never come here")


async def update_phone_for_recipe_id(
    recipe_id: str,
    user_id: str,
    phone: str,
    tenant_id: str,
    user_context: Dict[str, Any],
) -> Union[
    UserPutAPIOkResponse,
    UserPutAPIInvalidPhoneErrorResponse,
    UserPutPhoneAlreadyExistsAPIResponse,
]:
    validation_error: Optional[str] = None

    if recipe_id == "passwordless":
        validation_error = None

        passwordless_config = PasswordlessRecipe.get_instance().config.contact_config

        if isinstance(passwordless_config, ContactEmailOnlyConfig):
            validation_error = await default_validate_phone_number(phone, tenant_id)
        elif isinstance(
            passwordless_config, (ContactPhoneOnlyConfig, ContactEmailOrPhoneConfig)
        ):
            validation_error = await passwordless_config.validate_phone_number(
                phone, tenant_id
            )

        if validation_error is not None:
            return UserPutAPIInvalidPhoneErrorResponse(validation_error)

        update_result = await pless_update_user(
            user_id, phone_number=phone, user_context=user_context
        )

        if isinstance(update_result, PlessUpdateUserUnknownUserIdError):
            raise Exception("Should never come here")

        if isinstance(update_result, PhoneNumberAlreadyExistsError):
            return UserPutPhoneAlreadyExistsAPIResponse()

        return UserPutAPIOkResponse()

    if recipe_id == "thirdpartypasswordless":
        validation_error = None

        passwordless_config = (
            ThirdPartyPasswordlessRecipe.get_instance().passwordless_recipe.config.contact_config
        )

        if isinstance(passwordless_config, ContactEmailOnlyConfig):
            validation_error = await default_validate_phone_number(phone, tenant_id)

        elif isinstance(
            passwordless_config, (ContactPhoneOnlyConfig, ContactEmailOrPhoneConfig)
        ):
            validation_error = await passwordless_config.validate_phone_number(
                phone, tenant_id
            )

        if validation_error is not None:
            return UserPutAPIInvalidPhoneErrorResponse(validation_error)

        update_result = await pless_update_user(
            user_id, phone_number=phone, user_context=user_context
        )

        if isinstance(update_result, PlessUpdateUserUnknownUserIdError):
            raise Exception("Should never come here")

        if isinstance(update_result, PhoneNumberAlreadyExistsError):
            return UserPutPhoneAlreadyExistsAPIResponse()

        return UserPutAPIOkResponse()

    # If it comes here then the user is a third party user in which case the UI should not have allowed this
    raise Exception("Should never come here")


async def handle_user_put(
    _api_interface: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[
    UserPutAPIOkResponse,
    UserPutAPIInvalidEmailErrorResponse,
    UserPutAPIEmailAlreadyExistsErrorResponse,
    UserPutAPIInvalidPhoneErrorResponse,
    UserPutPhoneAlreadyExistsAPIResponse,
]:
    request_body: Dict[str, Any] = await api_options.request.json()  # type: ignore
    user_id: Optional[str] = request_body.get("userId")
    recipe_id: Optional[str] = request_body.get("recipeId")
    first_name: Optional[str] = request_body.get("firstName")
    last_name: Optional[str] = request_body.get("lastName")
    email: Optional[str] = request_body.get("email")
    phone: Optional[str] = request_body.get("phone")

    if not isinstance(user_id, str):
        return raise_bad_input_exception(
            "Required parameter 'userId' is missing or has an invalid type"
        )

    if not isinstance(recipe_id, str):
        return raise_bad_input_exception(
            "Required parameter 'recipeId' is missing or has an invalid type"
        )

    if not is_valid_recipe_id(recipe_id):
        raise_bad_input_exception("Invalid recipe id")

    if first_name is None and not isinstance(first_name, str):
        raise_bad_input_exception(
            "Required parameter 'firstName' is missing or has an invalid type"
        )

    if last_name is None and not isinstance(last_name, str):
        raise_bad_input_exception(
            "Required parameter 'lastName' is missing or has an invalid type"
        )

    if email is None and not isinstance(email, str):
        raise_bad_input_exception(
            "Required parameter 'email' is missing or has an invalid type"
        )

    if phone is None and not isinstance(phone, str):
        raise_bad_input_exception(
            "Required parameter 'phone' is missing or has an invalid type"
        )

    user_response = await get_user_for_recipe_id(user_id, recipe_id)

    if user_response is None:
        raise Exception("Should never come here")

    first_name = first_name.strip()
    last_name = last_name.strip()
    email = email.strip()
    phone = phone.strip()

    if first_name != "" or last_name != "":
        is_recipe_initialized = False

        try:
            UserMetadataRecipe.get_instance()
            is_recipe_initialized = True
        except Exception:
            pass

        if is_recipe_initialized:
            metadata_update = {}

            if first_name != "":
                metadata_update["first_name"] = first_name

            if last_name != "":
                metadata_update["last_name"] = last_name

            await update_user_metadata(user_id, metadata_update, user_context)

    if email != "":
        email_update_response = await update_email_for_recipe_id(
            user_response.recipe, user_id, email, tenant_id, user_context
        )

        if not isinstance(email_update_response, UserPutAPIOkResponse):
            return email_update_response

    if phone != "":
        phone_update_response = await update_phone_for_recipe_id(
            user_response.recipe, user_id, phone, tenant_id, user_context
        )

        if not isinstance(phone_update_response, UserPutAPIOkResponse):
            return phone_update_response

    return UserPutAPIOkResponse()
