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

from typing import TYPE_CHECKING, Any, Dict

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

    from .interfaces import APIInterface, RecipeInterface
    from .types import User, VerificationEmailTemplateVars


def default_get_email_verification_url(
    app_info: AppInfo,
) -> Callable[[User, Dict[str, Any]], Awaitable[str]]:
    async def func(_: User, __: Dict[str, Any]):
        return (
            app_info.website_domain.get_as_string_dangerous()
            + app_info.website_base_path.get_as_string_dangerous()
            + "/verify-email"
        )

    return func


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class ParentRecipeEmailVerificationConfig:
    def __init__(
        self,
        get_email_for_user_id: Callable[[str, Dict[str, Any]], Awaitable[str]],
        override: Union[OverrideConfig, None] = None,
        get_email_verification_url: Union[
            Callable[[User, Dict[str, Any]], Awaitable[str]], None
        ] = None,
        create_and_send_custom_email: Union[
            Callable[[User, str, Dict[str, Any]], Awaitable[None]], None
        ] = None,
        email_delivery: Union[
            EmailDeliveryConfig[VerificationEmailTemplateVars], None
        ] = None,
    ):
        self.override = override
        self.get_email_verification_url = get_email_verification_url
        self.get_email_for_user_id = get_email_for_user_id
        self.email_delivery = email_delivery
        self.create_and_send_custom_email = create_and_send_custom_email

        if create_and_send_custom_email:
            # Note: This will appear twice because `InputEmailVerificationConfig` will also produce same warning.
            deprecated_warn(
                "create_and_send_custom_email is deprecated. Please use email delivery config instead"
            )


class EmailVerificationConfig:
    def __init__(
        self,
        override: OverrideConfig,
        get_email_verification_url: Callable[[User, Dict[str, Any]], Awaitable[str]],
        get_email_for_user_id: Callable[[str, Dict[str, Any]], Awaitable[str]],
        get_email_delivery_config: Callable[
            [], EmailDeliveryConfigWithService[VerificationEmailTemplateVars]
        ],
    ):
        self.get_email_for_user_id = get_email_for_user_id
        self.get_email_verification_url = get_email_verification_url
        self.override = override
        self.get_email_delivery_config = get_email_delivery_config


def validate_and_normalise_user_input(
    app_info: AppInfo, config: ParentRecipeEmailVerificationConfig
) -> EmailVerificationConfig:
    if not isinstance(config, ParentRecipeEmailVerificationConfig):  # type: ignore
        raise ValueError(
            "config must be an instance of ParentRecipeEmailVerificationConfig"
        )

    get_email_verification_url = (
        config.get_email_verification_url
        if config.get_email_verification_url is not None
        else default_get_email_verification_url(app_info)
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
        override,
        get_email_verification_url,
        config.get_email_for_user_id,
        get_email_delivery_config,
    )
