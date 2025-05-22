# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from typing import Any, Dict, Union

from phonenumbers import PhoneNumberFormat, format_number
from phonenumbers import parse as parse_phone_number
from typing_extensions import Literal

from supertokens_python.exceptions import BadInputError
from supertokens_python.recipe.dashboard.interfaces import APIInterface, APIOptions
from supertokens_python.recipe.passwordless import (
    ContactEmailOnlyConfig,
    ContactEmailOrPhoneConfig,
    ContactPhoneOnlyConfig,
)
from supertokens_python.recipe.passwordless.asyncio import signinup
from supertokens_python.recipe.passwordless.recipe import PasswordlessRecipe
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.response import APIResponse


class CreatePasswordlessUserOkResponse(APIResponse):
    def __init__(
        self,
        created_new_recipe_user: bool,
        user: User,
        recipe_user_id: RecipeUserId,
    ):
        self.status: Literal["OK"] = "OK"
        self.created_new_recipe_user = created_new_recipe_user
        self.user = user
        self.recipe_user_id = recipe_user_id

    def to_json(self):
        return {
            "status": self.status,
            "createdNewRecipeUser": self.created_new_recipe_user,
            "user": self.user.to_json(),
            "recipeUserId": self.recipe_user_id.get_as_string(),
        }


class CreatePasswordlessUserFeatureNotEnabledResponse(APIResponse):
    def __init__(self):
        self.status: Literal["FEATURE_NOT_ENABLED_ERROR"] = "FEATURE_NOT_ENABLED_ERROR"

    def to_json(self):
        return {"status": self.status}


class CreatePasswordlessUserEmailValidationErrorResponse(APIResponse):
    def __init__(self, message: str):
        self.status: Literal["EMAIL_VALIDATION_ERROR"] = "EMAIL_VALIDATION_ERROR"
        self.message = message

    def to_json(self):
        return {"status": self.status, "message": self.message}


class CreatePasswordlessUserPhoneValidationErrorResponse(APIResponse):
    def __init__(self, message: str):
        self.status: Literal["PHONE_VALIDATION_ERROR"] = "PHONE_VALIDATION_ERROR"
        self.message = message

    def to_json(self):
        return {"status": self.status, "message": self.message}


async def create_passwordless_user(
    _: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    __: Dict[str, Any],
) -> Union[
    CreatePasswordlessUserOkResponse,
    CreatePasswordlessUserFeatureNotEnabledResponse,
    CreatePasswordlessUserEmailValidationErrorResponse,
    CreatePasswordlessUserPhoneValidationErrorResponse,
]:
    passwordless_recipe: PasswordlessRecipe
    try:
        passwordless_recipe = PasswordlessRecipe.get_instance()
    except Exception:
        return CreatePasswordlessUserFeatureNotEnabledResponse()

    request_body = await api_options.request.json()
    if request_body is None:
        raise BadInputError("Request body is missing")

    email = request_body.get("email")
    phone_number = request_body.get("phoneNumber")

    if (email is not None and phone_number is not None) or (
        email is None and phone_number is None
    ):
        raise BadInputError("Please provide exactly one of email or phoneNumber")

    if email is not None and (
        isinstance(
            passwordless_recipe.config.contact_config,
            (ContactEmailOnlyConfig, ContactEmailOrPhoneConfig),
        )
    ):
        email = email.strip()
        validation_error = (
            await passwordless_recipe.config.contact_config.validate_email_address(
                email, tenant_id
            )
        )
        if validation_error is not None:
            return CreatePasswordlessUserEmailValidationErrorResponse(validation_error)

    if phone_number is not None and (
        isinstance(
            passwordless_recipe.config.contact_config,
            (ContactPhoneOnlyConfig, ContactEmailOrPhoneConfig),
        )
    ):
        validation_error = (
            await passwordless_recipe.config.contact_config.validate_phone_number(
                phone_number, tenant_id
            )
        )
        if validation_error is not None:
            return CreatePasswordlessUserPhoneValidationErrorResponse(validation_error)

        try:
            parsed_phone_number = parse_phone_number(phone_number)
            phone_number = format_number(parsed_phone_number, PhoneNumberFormat.E164)
        except Exception:
            # This can happen if the user has provided their own impl of validate_phone_number
            # and the phone number is valid according to their impl, but not according to the phonenumbers lib.
            phone_number = phone_number.strip()

    response = await signinup(tenant_id, email=email, phone_number=phone_number)

    return CreatePasswordlessUserOkResponse(
        created_new_recipe_user=response.created_new_recipe_user,
        user=response.user,
        recipe_user_id=response.recipe_user_id,
    )
