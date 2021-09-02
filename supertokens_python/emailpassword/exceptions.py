"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""
from __future__ import annotations
from supertokens_python.exceptions import SuperTokensError
from typing import List, TYPE_CHECKING
if TYPE_CHECKING:
    from supertokens_python.recipe_module import RecipeModule
    from .types import ErrorFormField


def raise_form_field_exception(recipe, msg, form_fields):
    raise FieldError(recipe, msg, form_fields)


def raise_email_already_exists_exception(recipe, msg):
    if isinstance(msg, SuperTokensError):
        raise msg
    raise EmailAlreadyExistsError(recipe, msg) from None


def raise_wrong_credentials_exception(recipe, msg):
    if isinstance(msg, SuperTokensError):
        raise msg
    raise WrongCredentialsError(recipe, msg) from None


def raise_unknown_user_id_exception(recipe, msg):
    if isinstance(msg, SuperTokensError):
        raise msg
    raise UnknownUserIdError(recipe, msg) from None


def raise_unknown_email_exception(recipe, msg):
    if isinstance(msg, SuperTokensError):
        raise msg
    raise UnknownEmailError(recipe, msg) from None


def raise_reset_password_invalid_token_exception(recipe, msg):
    if isinstance(msg, SuperTokensError):
        raise msg
    raise ResetPasswordInvalidTokenError(recipe, msg) from None


class EmailAlreadyExistsError(SuperTokensError):
    pass


class FieldError(SuperTokensError):
    def __init__(self, recipe: RecipeModule, msg: str, form_fields: List[ErrorFormField]):
        super().__init__(recipe, msg)
        self.form_fields = form_fields

    def get_json_form_fields(self):
        form_fields = []
        for form_field in self.form_fields:
            form_fields.append({
                'id': form_field.id,
                'error': form_field.error
            })


class WrongCredentialsError(SuperTokensError):
    pass


class UnknownUserIdError(SuperTokensError):
    pass


class UnknownEmailError(SuperTokensError):
    pass


class ResetPasswordInvalidTokenError(SuperTokensError):
    pass
