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
from typing import Awaitable, Callable, List, TypeVar, Union

from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryInterface,
    SMTPServiceInterface,
)


class User:
    def __init__(self, user_id: str, email: str, time_joined: int):
        self.user_id: str = user_id
        self.email: str = email
        self.time_joined: int = time_joined


class UsersResponse:
    def __init__(self, users: List[User], next_pagination_token: Union[str, None]):
        self.users = users
        self.next_pagination_token = next_pagination_token


class ErrorFormField:
    def __init__(self, id: str, error: str):  # pylint: disable=redefined-builtin
        self.id = id
        self.error = error


class FormField:
    def __init__(self, id: str, value: str):  # pylint: disable=redefined-builtin
        self.id: str = id
        self.value: str = value


class InputFormField:
    def __init__(
        self,
        id: str,  # pylint: disable=redefined-builtin
        validate: Union[
            Callable[[str], Awaitable[Union[str, None]]],
            None,
        ] = None,
        optional: Union[bool, None] = None,
    ):
        self.id = id
        self.validate = validate
        self.optional = optional


class NormalisedFormField:
    def __init__(
        self,
        id: str,  # pylint: disable=redefined-builtin
        validate: Callable[[str], Awaitable[Union[str, None]]],
        optional: bool,
    ):
        self.id = id
        self.validate = validate
        self.optional = optional


_T = TypeVar("_T")


class PasswordResetEmailTemplateVarsUser:
    def __init__(self, user_id: str, email: str):
        self.id = user_id
        self.email = email


class PasswordResetEmailTemplateVars:
    def __init__(
        self,
        user: PasswordResetEmailTemplateVarsUser,
        password_reset_link: str,
    ) -> None:
        self.user = user
        self.password_reset_link = password_reset_link


# Export:
EmailTemplateVars = PasswordResetEmailTemplateVars

# PasswordResetEmailTemplateVars (Already exported because it's defined in the same)

SMTPOverrideInput = SMTPServiceInterface[EmailTemplateVars]

EmailDeliveryOverrideInput = EmailDeliveryInterface[EmailTemplateVars]


class EmailPasswordIngredients:
    def __init__(
        self,
        email_delivery: Union[EmailDeliveryIngredient[EmailTemplateVars], None] = None,
    ) -> None:
        self.email_delivery = email_delivery
