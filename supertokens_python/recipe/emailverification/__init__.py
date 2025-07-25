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

from typing import TYPE_CHECKING, Optional, Union

from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig

from .emaildelivery.services import SMTPService
from .interfaces import TypeGetEmailForUserIdFunction
from .recipe import EmailVerificationClaim, EmailVerificationRecipe
from .types import EmailDeliveryInterface, EmailTemplateVars
from .utils import MODE_TYPE, EmailVerificationOverrideConfig, InputOverrideConfig

if TYPE_CHECKING:
    from supertokens_python.supertokens import RecipeInit


def init(
    mode: MODE_TYPE,
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
    get_email_for_recipe_user_id: Optional[TypeGetEmailForUserIdFunction] = None,
    override: Union[EmailVerificationOverrideConfig, None] = None,
) -> RecipeInit:
    return EmailVerificationRecipe.init(
        mode,
        email_delivery,
        get_email_for_recipe_user_id,
        override,
    )


__all__ = [
    "EmailDeliveryInterface",
    "EmailTemplateVars",
    "EmailVerificationClaim",
    "EmailVerificationOverrideConfig",
    "EmailVerificationRecipe",
    "InputOverrideConfig",  # deprecated, use EmailVerificationOverrideConfig instead
    "SMTPService",
    "TypeGetEmailForUserIdFunction",
    "init",
]
