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

from typing import TYPE_CHECKING, Any, Dict, Optional
from supertokens_python.framework import BaseRequest

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryConfigWithService,
)
from supertokens_python.recipe.emailverification.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService,
)
from typing_extensions import Literal

if TYPE_CHECKING:
    from typing import Callable, Union

    from supertokens_python.supertokens import AppInfo

    from .interfaces import APIInterface, RecipeInterface, TypeGetEmailForUserIdFunction
    from .types import EmailTemplateVars, VerificationEmailTemplateVars


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


MODE_TYPE = Literal["REQUIRED", "OPTIONAL"]


class EmailVerificationConfig:
    def __init__(
        self,
        mode: MODE_TYPE,
        get_email_delivery_config: Callable[
            [], EmailDeliveryConfigWithService[VerificationEmailTemplateVars]
        ],
        get_email_for_user_id: Optional[TypeGetEmailForUserIdFunction],
        override: OverrideConfig,
    ):
        self.mode = mode
        self.override = override
        self.get_email_delivery_config = get_email_delivery_config
        self.get_email_for_user_id = get_email_for_user_id


def validate_and_normalise_user_input(
    app_info: AppInfo,
    mode: MODE_TYPE,
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
    get_email_for_user_id: Optional[TypeGetEmailForUserIdFunction] = None,
    override: Union[OverrideConfig, None] = None,
) -> EmailVerificationConfig:
    if mode not in ["REQUIRED", "OPTIONAL"]:
        raise ValueError(
            "Email Verification recipe mode must be one of 'REQUIRED' or 'OPTIONAL'"
        )

    def get_email_delivery_config() -> EmailDeliveryConfigWithService[
        VerificationEmailTemplateVars
    ]:
        email_service = email_delivery.service if email_delivery is not None else None
        if email_service is None:
            email_service = BackwardCompatibilityService(app_info)

        if email_delivery is not None and email_delivery.override is not None:
            override = email_delivery.override
        else:
            override = None
        return EmailDeliveryConfigWithService(email_service, override=override)

    if override is not None and not isinstance(override, OverrideConfig):  # type: ignore
        raise ValueError("override must be of type OverrideConfig or None")

    if override is None:
        override = OverrideConfig()

    return EmailVerificationConfig(
        mode,
        get_email_delivery_config,
        get_email_for_user_id,
        override,
    )


def get_email_verify_link(
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
        + "/verify-email"
        + "?token="
        + token
        + "&rid="
        + recipe_id
        + "&tenantId="
        + tenant_id
    )
