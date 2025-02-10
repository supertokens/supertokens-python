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

from typing import Any, Awaitable, Callable, Dict, Optional, TypeVar, Union

from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryInterface,
    SMTPServiceInterface,
)
from supertokens_python.types import RecipeUserId


class ErrorFormField:
    def __init__(self, id: str, error: str):  # pylint: disable=redefined-builtin
        self.id = id
        self.error = error


class FormField:
    def __init__(self, id: str, value: Any):  # pylint: disable=redefined-builtin
        self.id: str = id
        self.value: Any = value

    def to_json(self) -> Dict[str, Any]:
        return {"id": self.id, "value": self.value}


class InputFormField:
    def __init__(
        self,
        id: str,  # pylint: disable=redefined-builtin
        validate: Union[
            Callable[[str, str], Awaitable[Union[str, None]]],
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
        validate: Callable[[str, str], Awaitable[Union[str, None]]],
        optional: bool,
    ):
        self.id = id
        self.validate = validate
        self.optional = optional


_T = TypeVar("_T")


class PasswordResetEmailTemplateVarsUser:
    def __init__(
        self, user_id: str, recipe_user_id: Optional[RecipeUserId], email: str
    ):
        self.id = user_id
        self.recipe_user_id = recipe_user_id
        self.email = email

    def to_json(self) -> Dict[str, Any]:
        resp_json = {
            "id": self.id,
            "recipeUserId": (
                self.recipe_user_id.get_as_string()
                if self.recipe_user_id is not None
                else None
            ),
            "email": self.email,
        }
        # Remove items that are None
        return {k: v for k, v in resp_json.items() if v is not None}


class PasswordResetEmailTemplateVars:
    def __init__(
        self,
        user: PasswordResetEmailTemplateVarsUser,
        password_reset_link: str,
        tenant_id: str,
    ) -> None:
        self.user = user
        self.password_reset_link = password_reset_link
        self.tenant_id = tenant_id

    def to_json(self) -> Dict[str, Any]:
        return {
            "type": "PASSWORD_RESET",
            "user": self.user.to_json(),
            "passwordResetLink": self.password_reset_link,
            "tenantId": self.tenant_id,
        }


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
