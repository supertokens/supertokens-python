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

from typing import Union, Dict, Any

from supertokens_python.ingredients.emaildelivery import \
    EmailDeliveryIngredient


class User:
    def __init__(self, user_id: str, email: str):
        self.user_id = user_id
        self.email = email


class TypeEmailVerificationEmailDeliveryInputUser:
    def __init__(self, user_id: str, email: str):
        self.id = user_id
        self.email = email


class VerificationEmailTemplateVars:
    def __init__(
        self,
        user: TypeEmailVerificationEmailDeliveryInputUser,
        email_verify_link: str,
        user_context: Dict[str, Any],
    ) -> None:
        self.user = user
        self.email_verify_link = email_verify_link
        self.user_context = user_context


# Export:
EmailTemplateVars = VerificationEmailTemplateVars


class EmailVerificationIngredients:
    def __init__(self, email_delivery: Union[EmailDeliveryIngredient[VerificationEmailTemplateVars], None] = None):
        self.email_delivery = email_delivery
