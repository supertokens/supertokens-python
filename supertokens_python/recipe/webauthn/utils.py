# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
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

from re import fullmatch
from typing import Any, Optional, Union
from urllib.parse import urlparse

from supertokens_python.framework.request import BaseRequest
from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfigWithService,
)
from supertokens_python.recipe.webauthn.emaildelivery.services.backward_compatibility.base import (
    BackwardCompatibilityService,
)
from supertokens_python.recipe.webauthn.interfaces.api import (
    TypeWebauthnEmailDeliveryInput,
)
from supertokens_python.recipe.webauthn.types.config import (
    GetOrigin,
    GetRelyingPartyId,
    GetRelyingPartyName,
    NormalisedGetOrigin,
    NormalisedGetRelyingPartyId,
    NormalisedGetRelyingPartyName,
    NormalisedValidateEmailAddress,
    NormalisedWebauthnConfig,
    OverrideConfig,
    ValidateEmailAddress,
    WebauthnConfig,
)
from supertokens_python.supertokens import AppInfo
from supertokens_python.types.base import UserContext


def validate_and_normalise_user_input(
    app_info: AppInfo, config: Optional[WebauthnConfig]
) -> NormalisedWebauthnConfig:
    if config is None:
        config = WebauthnConfig()

    get_relying_party_id = validate_and_normalise_relying_party_id_config(
        app_info, config.get_relying_party_id
    )
    get_relying_party_name = validate_and_normalise_relying_party_name_config(
        app_info, config.get_relying_party_name
    )
    get_origin = validate_and_normalise_get_origin_config(app_info, config.get_origin)
    validate_email_address = validate_and_normalise_validate_email_address_config(
        config.validate_email_address
    )

    if config.override is None:
        override = OverrideConfig()
    else:
        override = OverrideConfig(
            functions=config.override.functions,
            apis=config.override.apis,
        )

    def get_email_delivery_config() -> EmailDeliveryConfigWithService[
        TypeWebauthnEmailDeliveryInput
    ]:
        if config.email_delivery is not None and config.email_delivery.service:
            return EmailDeliveryConfigWithService(
                service=config.email_delivery.service,
                override=config.email_delivery.override,
            )

        email_service = BackwardCompatibilityService(app_info=app_info)
        if (
            config.email_delivery is not None
            and config.email_delivery.override is not None
        ):
            override = config.email_delivery.override
        else:
            override = None
        return EmailDeliveryConfigWithService(email_service, override=override)

    return NormalisedWebauthnConfig(
        get_relying_party_id=get_relying_party_id,
        get_relying_party_name=get_relying_party_name,
        get_origin=get_origin,
        get_email_delivery_config=get_email_delivery_config,
        validate_email_address=validate_email_address,
        override=override,
    )


def validate_and_normalise_relying_party_id_config(
    app_info: AppInfo, relying_party_id_config: Optional[Union[str, GetRelyingPartyId]]
) -> NormalisedGetRelyingPartyId:
    async def inner_fn(
        *, tenant_id: str, request: Optional[BaseRequest], user_context: UserContext
    ) -> str:
        if isinstance(relying_party_id_config, str):
            return relying_party_id_config

        if callable(relying_party_id_config):
            return await relying_party_id_config(
                tenant_id=tenant_id,
                request=request,
                user_context=user_context,
            )

        url_string = app_info.api_domain.get_as_string_dangerous()
        url = urlparse(url_string)

        if url.hostname is None:
            raise Exception("get_relying_party_id parsed a URL with no hostname")

        return url.hostname

    return inner_fn


def validate_and_normalise_relying_party_name_config(
    app_info: AppInfo,
    relying_party_name_config: Optional[Union[str, GetRelyingPartyName]],
) -> NormalisedGetRelyingPartyName:
    async def inner_fn(
        *, tenant_id: str, request: Optional[BaseRequest], user_context: UserContext
    ) -> str:
        if isinstance(relying_party_name_config, str):
            return relying_party_name_config

        if callable(relying_party_name_config):
            return await relying_party_name_config(
                tenant_id=tenant_id, user_context=user_context
            )

        return app_info.app_name

    return inner_fn


async def default_email_validator(value: Any, _tenant_id: str) -> Optional[str]:
    # We check if the email syntax is correct
    # As per https://github.com/supertokens/supertokens-auth-react/issues/5#issuecomment-709512438
    # Regex from https://stackoverflow.com/a/46181/3867175
    if (not isinstance(value, str)) or (
        fullmatch(
            r'^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,'
            r"3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$",
            value,
        )
        is None
    ):
        return "Email is not valid"

    return None


def validate_and_normalise_validate_email_address_config(
    validate_email_address_config: Optional[ValidateEmailAddress],
) -> NormalisedValidateEmailAddress:
    async def inner_fn(
        *, email: str, tenant_id: str, user_context: UserContext
    ) -> Optional[str]:
        if isinstance(validate_email_address_config, str):
            return validate_email_address_config

        if callable(validate_email_address_config):
            return await validate_email_address_config(
                email=email,
                tenant_id=tenant_id,
                user_context=user_context,
            )

        return await default_email_validator(email, tenant_id)

    return inner_fn


def validate_and_normalise_get_origin_config(
    app_info: AppInfo,
    get_origin_config: Optional[GetOrigin],
) -> NormalisedGetOrigin:
    async def inner_fn(
        *, tenant_id: str, request: Optional[BaseRequest], user_context: UserContext
    ) -> str:
        if callable(get_origin_config):
            return await get_origin_config(
                tenant_id=tenant_id,
                request=request,
                user_context=user_context,
            )

        return app_info.get_origin(
            request=request, user_context=user_context
        ).get_as_string_dangerous()

    return inner_fn


def get_recover_account_link(
    app_info: AppInfo,
    token: str,
    tenant_id: str,
    request: Optional[BaseRequest],
    user_context: UserContext,
) -> str:
    origin = app_info.get_origin(
        request=request, user_context=user_context
    ).get_as_string_dangerous()
    website_base_path = app_info.website_base_path.get_as_string_dangerous()

    return f"{origin}{website_base_path}/webauthn/recover?token={token}&tenantId={tenant_id}"
