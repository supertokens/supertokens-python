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

from typing import Any, Dict, Union

from supertokens_python.ingredients.emaildelivery import EmailDeliveryIngredient
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryInterface,
    SMTPServiceInterface,
)
from supertokens_python.types import RecipeUserId


class EmailVerificationUser:
    def __init__(self, recipe_user_id: RecipeUserId, email: str):
        self.recipe_user_id = recipe_user_id
        self.email = email

    def to_json(self) -> Dict[str, Any]:
        return {
            "recipeUserId": self.recipe_user_id.get_as_string(),
            "email": self.email,
        }


class VerificationEmailTemplateVarsUser:
    def __init__(self, _id: str, recipe_user_id: RecipeUserId, email: str):
        self.id = _id
        self.recipe_user_id = recipe_user_id
        self.email = email

    def to_json(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "recipeUserId": self.recipe_user_id.get_as_string(),
            "email": self.email,
        }


class VerificationEmailTemplateVars:
    def __init__(
        self,
        user: VerificationEmailTemplateVarsUser,
        email_verify_link: str,
        tenant_id: str,
    ) -> None:
        self.user = user
        self.email_verify_link = email_verify_link
        self.tenant_id = tenant_id


# Export:
EmailTemplateVars = VerificationEmailTemplateVars

SMTPOverrideInput = SMTPServiceInterface[EmailTemplateVars]

EmailDeliveryOverrideInput = EmailDeliveryInterface[EmailTemplateVars]


class EmailVerificationIngredients:
    def __init__(
        self,
        email_delivery: Union[EmailDeliveryIngredient[EmailTemplateVars], None] = None,
    ):
        self.email_delivery = email_delivery
