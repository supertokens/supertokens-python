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

from typing import TYPE_CHECKING, Callable, Union, Optional

from . import exceptions as ex
from . import utils
from .emaildelivery import services as emaildelivery_services
from . import recipe
from . import types
from .interfaces import TypeGetEmailForUserIdFunction
from .recipe import EmailVerificationRecipe
from .types import EmailTemplateVars
from ...ingredients.emaildelivery.types import EmailDeliveryConfig

InputOverrideConfig = utils.OverrideConfig
exception = ex
SMTPService = emaildelivery_services.SMTPService
EmailVerificationClaim = recipe.EmailVerificationClaim
EmailDeliveryInterface = types.EmailDeliveryInterface


if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo

    from ...recipe_module import RecipeModule

from .utils import MODE_TYPE, OverrideConfig


def init(
    mode: MODE_TYPE,
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
    get_email_for_user_id: Optional[TypeGetEmailForUserIdFunction] = None,
    override: Union[OverrideConfig, None] = None,
) -> Callable[[AppInfo], RecipeModule]:
    return EmailVerificationRecipe.init(
        mode,
        email_delivery,
        get_email_for_user_id,
        override,
    )
