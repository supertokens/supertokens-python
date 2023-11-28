# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
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
from __future__ import annotations

from re import fullmatch
from typing import TYPE_CHECKING, Any, Callable, List, Optional, Union, Dict
from supertokens_python.framework import BaseRequest

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryConfigWithService,
)
from supertokens_python.recipe.emailpassword.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService,
)

from .interfaces import APIInterface, RecipeInterface
from .types import InputFormField, NormalisedFormField, EmailTemplateVars

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo

from supertokens_python.utils import get_filtered_list

from .constants import (
    FORM_FIELD_EMAIL_ID,
    FORM_FIELD_PASSWORD_ID,
)


async def default_validator(_: str, __: str) -> Union[str, None]:
    return None


async def default_password_validator(value: str, _tenant_id: str) -> Union[str, None]:
    # length >= 8 && < 100
    # must have a number and a character
    # as per
    # https://github.com/supertokens/supertokens-auth-react/issues/5#issuecomment-709512438
    if len(value) < 8:
        return "Password must contain at least 8 characters, including a number"

    if len(value) >= 100:
        return "Password's length must be lesser than 100 characters"

    if fullmatch(r"^.*[A-Za-z]+.*$", value) is None:
        return "Password must contain at least one alphabet"

    if fullmatch(r"^.*[0-9]+.*$", value) is None:
        return "Password must contain at least one number"

    return None


async def default_email_validator(value: Any, _tenant_id: str) -> Union[str, None]:
    # We check if the email syntax is correct
    # As per https://github.com/supertokens/supertokens-auth-react/issues/5#issuecomment-709512438
    # Regex from https://stackoverflow.com/a/46181/3867175
    if (not isinstance(value, str)) or (
        fullmatch(
            r'^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,'
            r"3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$",
            value,
        )
        is None
    ):
        return "Email is not valid"

    return None


class InputSignUpFeature:
    def __init__(self, form_fields: Union[List[InputFormField], None] = None):
        if form_fields is None:
            form_fields = []
        self.form_fields = normalise_sign_up_form_fields(form_fields)


class SignUpFeature:
    def __init__(self, form_fields: List[NormalisedFormField]):
        self.form_fields = form_fields


def normalise_sign_up_form_fields(
    form_fields: List[InputFormField],
) -> List[NormalisedFormField]:
    normalised_form_fields: List[NormalisedFormField] = []
    for field in form_fields:
        if field.id == FORM_FIELD_PASSWORD_ID:
            validator = (
                field.validate
                if field.validate is not None
                else default_password_validator
            )
            normalised_form_fields.append(
                NormalisedFormField(field.id, validator, False)
            )
        elif field.id == FORM_FIELD_EMAIL_ID:
            validator = (
                field.validate
                if field.validate is not None
                else default_email_validator
            )
            normalised_form_fields.append(
                NormalisedFormField(field.id, validator, False)
            )
        else:
            validator = (
                field.validate if field.validate is not None else default_validator
            )
            optional = field.optional if field.optional is not None else False
            normalised_form_fields.append(
                NormalisedFormField(field.id, validator, optional)
            )
    if (
        len(
            get_filtered_list(
                lambda x: x.id == FORM_FIELD_PASSWORD_ID, normalised_form_fields
            )
        )
        == 0
    ):
        normalised_form_fields.append(
            NormalisedFormField(
                FORM_FIELD_PASSWORD_ID, default_password_validator, False
            )
        )
    if (
        len(
            get_filtered_list(
                lambda x: x.id == FORM_FIELD_EMAIL_ID, normalised_form_fields
            )
        )
        == 0
    ):
        normalised_form_fields.append(
            NormalisedFormField(FORM_FIELD_EMAIL_ID, default_email_validator, False)
        )
    return normalised_form_fields


class SignInFeature:
    def __init__(self, form_fields: List[NormalisedFormField]):
        self.form_fields = form_fields


def normalise_sign_in_form_fields(
    form_fields: List[NormalisedFormField],
) -> List[NormalisedFormField]:
    return list(
        map(
            lambda y: NormalisedFormField(
                y.id,
                y.validate if y.id == FORM_FIELD_EMAIL_ID else default_validator,
                False,
            ),
            get_filtered_list(
                lambda x: x.id in (FORM_FIELD_PASSWORD_ID, FORM_FIELD_EMAIL_ID),
                form_fields,
            ),
        )
    )


def validate_and_normalise_sign_in_config(
    sign_up_config: SignUpFeature,
) -> SignInFeature:
    form_fields = normalise_sign_in_form_fields(sign_up_config.form_fields)
    return SignInFeature(form_fields)


class ResetPasswordUsingTokenFeature:
    def __init__(
        self,
        form_fields_for_password_reset_form: List[NormalisedFormField],
        form_fields_for_generate_token_form: List[NormalisedFormField],
    ):
        self.form_fields_for_password_reset_form = form_fields_for_password_reset_form
        self.form_fields_for_generate_token_form = form_fields_for_generate_token_form


def validate_and_normalise_reset_password_using_token_config(
    sign_up_config: InputSignUpFeature,
) -> ResetPasswordUsingTokenFeature:
    form_fields_for_password_reset_form = list(
        map(
            lambda y: NormalisedFormField(y.id, y.validate, False),
            get_filtered_list(
                lambda x: x.id == FORM_FIELD_PASSWORD_ID, sign_up_config.form_fields
            ),
        )
    )
    form_fields_for_generate_token_form = list(
        map(
            lambda y: NormalisedFormField(y.id, y.validate, False),
            get_filtered_list(
                lambda x: x.id == FORM_FIELD_EMAIL_ID, sign_up_config.form_fields
            ),
        )
    )

    return ResetPasswordUsingTokenFeature(
        form_fields_for_password_reset_form,
        form_fields_for_generate_token_form,
    )


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class EmailPasswordConfig:
    def __init__(
        self,
        sign_up_feature: SignUpFeature,
        sign_in_feature: SignInFeature,
        reset_password_using_token_feature: ResetPasswordUsingTokenFeature,
        override: OverrideConfig,
        get_email_delivery_config: Callable[
            [RecipeInterface], EmailDeliveryConfigWithService[EmailTemplateVars]
        ],
    ):
        self.sign_up_feature = sign_up_feature
        self.sign_in_feature = sign_in_feature
        self.reset_password_using_token_feature = reset_password_using_token_feature
        self.override = override
        self.get_email_delivery_config = get_email_delivery_config


def validate_and_normalise_user_input(
    app_info: AppInfo,
    sign_up_feature: Union[InputSignUpFeature, None] = None,
    override: Union[InputOverrideConfig, None] = None,
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
) -> EmailPasswordConfig:

    if sign_up_feature is not None and not isinstance(sign_up_feature, InputSignUpFeature):  # type: ignore
        raise ValueError("sign_up_feature must be of type InputSignUpFeature or None")

    if override is not None and not isinstance(override, InputOverrideConfig):  # type: ignore
        raise ValueError("override must be of type InputOverrideConfig or None")

    if override is None:
        override = InputOverrideConfig()

    if sign_up_feature is None:
        sign_up_feature = InputSignUpFeature()

    def get_email_delivery_config(
        ep_recipe: RecipeInterface,
    ) -> EmailDeliveryConfigWithService[EmailTemplateVars]:
        if email_delivery and email_delivery.service:
            return EmailDeliveryConfigWithService(
                service=email_delivery.service, override=email_delivery.override
            )

        email_service = BackwardCompatibilityService(
            app_info=app_info,
            recipe_interface_impl=ep_recipe,
        )
        if email_delivery is not None and email_delivery.override is not None:
            override = email_delivery.override
        else:
            override = None
        return EmailDeliveryConfigWithService(email_service, override=override)

    return EmailPasswordConfig(
        SignUpFeature(sign_up_feature.form_fields),
        SignInFeature(normalise_sign_in_form_fields(sign_up_feature.form_fields)),
        validate_and_normalise_reset_password_using_token_config(sign_up_feature),
        OverrideConfig(functions=override.functions, apis=override.apis),
        get_email_delivery_config=get_email_delivery_config,
    )


def get_password_reset_link(
    app_info: AppInfo,
    token: str,
    recipe_id: str,
    tenant_id: str,
    request: Optional[BaseRequest],
    user_context: Dict[str, Any],
) -> str:
    return (
        app_info.get_origin(request, user_context).get_as_string_dangerous()
        + app_info.website_base_path.get_as_string_dangerous()
        + "/reset-password?token="
        + token
        + "&rid="
        + recipe_id
        + "&tenantId="
        + tenant_id
    )
