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
from typing_extensions import Literal
from typing import TYPE_CHECKING, Any, Dict, Optional

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryConfigWithService,
)
from supertokens_python.recipe.emailverification.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService,
)
from supertokens_python.utils import deprecated_warn

if TYPE_CHECKING:
    from typing import Awaitable, Callable, Union

    from supertokens_python.supertokens import AppInfo

    from .interfaces import APIInterface, RecipeInterface, TypeGetEmailForUserIdFunction
    from .types import User, VerificationEmailTemplateVars, EmailTemplateVars


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class ParentRecipeEmailVerificationConfig:
    # TODO: Now that this class is public, we might want to rename this?
    def __init__(
        self,
        mode: Literal["REQUIRED", "OPTIONAL"],
        email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None,
        get_email_for_user_id: Optional[TypeGetEmailForUserIdFunction] = None,
        create_and_send_custom_email: Union[
            Callable[[User, str, Dict[str, Any]], Awaitable[None]], None
        ] = None,
        override: Union[OverrideConfig, None] = None,
    ):
        self.mode = mode
        self.email_delivery = email_delivery
        self.get_email_for_user_id = get_email_for_user_id
        self.create_and_send_custom_email = create_and_send_custom_email
        self.override = override

        if create_and_send_custom_email:
            # Note: This will appear twice because `InputEmailVerificationConfig` will also produce same warning.
            deprecated_warn(
                "create_and_send_custom_email is deprecated. Please use email delivery config instead"
            )


class EmailVerificationConfig:
    def __init__(
        self,
        mode: str,  # TODO: Literal["REQUIRED", "OPTIONAL"] had to be removed because of pyright. Possible to avoid?
        get_email_delivery_config: Callable[
            [], EmailDeliveryConfigWithService[VerificationEmailTemplateVars]
        ],
        get_email_for_user_id: Optional[TypeGetEmailForUserIdFunction],
        override: OverrideConfig,
    ):
        self.mode: str = mode  # TODO: How to avoid ": str"
        self.override = override
        self.get_email_delivery_config = get_email_delivery_config
        self.get_email_for_user_id = get_email_for_user_id


def validate_and_normalise_user_input(
    app_info: AppInfo, config: ParentRecipeEmailVerificationConfig
) -> EmailVerificationConfig:
    if not isinstance(config, ParentRecipeEmailVerificationConfig):  # type: ignore
        raise ValueError(
            "config must be an instance of ParentRecipeEmailVerificationConfig"
        )

    def get_email_delivery_config() -> EmailDeliveryConfigWithService[
        VerificationEmailTemplateVars
    ]:
        email_service = (
            config.email_delivery.service if config.email_delivery is not None else None
        )
        if email_service is None:
            email_service = BackwardCompatibilityService(
                app_info, config.create_and_send_custom_email
            )

        if (
            config.email_delivery is not None
            and config.email_delivery.override is not None
        ):
            override = config.email_delivery.override
        else:
            override = None
        return EmailDeliveryConfigWithService(email_service, override=override)

    override = config.override

    if override is not None and not isinstance(override, OverrideConfig):  # type: ignore
        raise ValueError("override must be of type OverrideConfig or None")

    if override is None:
        override = OverrideConfig()

    return EmailVerificationConfig(
        config.mode,
        get_email_delivery_config,
        config.get_email_for_user_id,
        override,
    )
