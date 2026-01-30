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

from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Union

from typing_extensions import Literal

from supertokens_python.framework import BaseRequest
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig,
    EmailDeliveryConfigWithService,
)
from supertokens_python.recipe.emailverification.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService,
)
from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideableConfig,
    BaseOverrideConfig,
)

from .interfaces import APIInterface, RecipeInterface, TypeGetEmailForUserIdFunction
from .types import EmailTemplateVars, VerificationEmailTemplateVars

if TYPE_CHECKING:
    from supertokens_python.supertokens import AppInfo


MODE_TYPE = Literal["REQUIRED", "OPTIONAL"]

EmailVerificationOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedEmailVerificationOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]
InputOverrideConfig = EmailVerificationOverrideConfig
"""Deprecated, use `EmailVerificationOverrideConfig` instead."""


class EmailVerificationOverrideableConfig(BaseOverrideableConfig):
    """Input config properties overrideable using the plugin config overrides"""

    mode: MODE_TYPE
    email_delivery: Union[EmailDeliveryConfig[EmailTemplateVars], None] = None
    get_email_for_recipe_user_id: Optional[TypeGetEmailForUserIdFunction] = None


class EmailVerificationConfig(
    EmailVerificationOverrideableConfig,
    BaseConfig[RecipeInterface, APIInterface, EmailVerificationOverrideableConfig],
):
    def to_overrideable_config(self) -> EmailVerificationOverrideableConfig:
        """Create a `EmailVerificationOverrideableConfig` from the current config."""
        return EmailVerificationOverrideableConfig(**self.model_dump())

    def from_overrideable_config(
        self,
        overrideable_config: EmailVerificationOverrideableConfig,
    ) -> "EmailVerificationConfig":
        """
        Create a `EmailVerificationConfig` from a `EmailVerificationOverrideableConfig`.
        Not a classmethod since it needs to be used in a dynamic context within plugins.
        """
        return EmailVerificationConfig(
            **overrideable_config.model_dump(),
            override=self.override,
        )


class NormalisedEmailVerificationConfig(
    BaseNormalisedConfig[RecipeInterface, APIInterface]
):
    mode: MODE_TYPE
    get_email_delivery_config: Callable[
        [], EmailDeliveryConfigWithService[VerificationEmailTemplateVars]
    ]
    get_email_for_recipe_user_id: Optional[TypeGetEmailForUserIdFunction]


def validate_and_normalise_user_input(
    app_info: AppInfo,
    config: EmailVerificationConfig,
) -> NormalisedEmailVerificationConfig:
    if config.mode not in ["REQUIRED", "OPTIONAL"]:
        raise ValueError(
            "Email Verification recipe mode must be one of 'REQUIRED' or 'OPTIONAL'"
        )

    def get_email_delivery_config() -> EmailDeliveryConfigWithService[
        VerificationEmailTemplateVars
    ]:
        email_service = (
            config.email_delivery.service if config.email_delivery is not None else None
        )
        if email_service is None:
            email_service = BackwardCompatibilityService(app_info)

        if (
            config.email_delivery is not None
            and config.email_delivery.override is not None
        ):
            override = config.email_delivery.override
        else:
            override = None
        return EmailDeliveryConfigWithService(email_service, override=override)

    override_config = NormalisedEmailVerificationOverrideConfig.from_input_config(
        override_config=config.override
    )

    return NormalisedEmailVerificationConfig(
        mode=config.mode,
        get_email_delivery_config=get_email_delivery_config,
        get_email_for_recipe_user_id=config.get_email_for_recipe_user_id,
        override=override_config,
    )


def get_email_verify_link(
    app_info: AppInfo,
    token: str,
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
        + "&tenantId="
        + tenant_id
    )
