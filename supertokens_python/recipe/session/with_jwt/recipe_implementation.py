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

from typing import TYPE_CHECKING, Any, Dict, Union, Optional

from jwt import decode

from supertokens_python.utils import get_timestamp_ms

from .constants import ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY
from .session_class import get_session_with_jwt
from .utills import add_jwt_to_access_token_payload

if TYPE_CHECKING:
    from supertokens_python.recipe.session.utils import SessionConfig
    from supertokens_python.recipe.session.interfaces import (
        RecipeInterface,
        SessionContainer,
        SessionInformationResult,
    )
    from supertokens_python.framework.types import BaseRequest

from math import ceil

from supertokens_python.recipe.openid.interfaces import (
    RecipeInterface as OpenIdRecipeInterface,
)

EXPIRY_OFFSET_SECONDS = 30


def get_jwt_expiry(access_token_expiry: int):
    return access_token_expiry + EXPIRY_OFFSET_SECONDS


def get_recipe_implementation_with_jwt(
    original_implementation: RecipeInterface,
    config: SessionConfig,
    openid_recipe_implementation: OpenIdRecipeInterface,
) -> RecipeInterface:

    og_create_new_session = original_implementation.create_new_session

    async def create_new_session(
        request: BaseRequest,
        user_id: str,
        access_token_payload: Union[None, Dict[str, Any]],
        session_data: Union[None, Dict[str, Any]],
        user_context: Dict[str, Any],
    ) -> SessionContainer:
        if access_token_payload is None:
            access_token_payload = {}
        access_token_validity_in_seconds = ceil(
            await original_implementation.get_access_token_lifetime_ms(user_context)
            / 1000
        )
        access_token_payload = await add_jwt_to_access_token_payload(
            access_token_payload=access_token_payload,
            jwt_expiry=get_jwt_expiry(access_token_validity_in_seconds),
            user_id=user_id,
            jwt_property_name=config.jwt.property_name_in_access_token_payload,
            openid_recipe_implementation=openid_recipe_implementation,
            user_context=user_context,
        )
        session = await og_create_new_session(
            request,
            user_id,
            access_token_payload,
            session_data,
            user_context=user_context,
        )
        return get_session_with_jwt(session, openid_recipe_implementation)

    og_get_session = original_implementation.get_session

    async def get_session(
        request: BaseRequest,
        anti_csrf_check: Union[bool, None],
        session_required: bool,
        user_context: Dict[str, Any],
    ) -> Union[SessionContainer, None]:
        session_container = await og_get_session(
            request,
            anti_csrf_check,
            session_required,
            user_context,
        )
        if session_container is None:
            return None
        return get_session_with_jwt(session_container, openid_recipe_implementation)

    og_refresh_session = original_implementation.refresh_session

    async def refresh_session(
        request: BaseRequest, user_context: Dict[str, Any]
    ) -> SessionContainer:
        access_token_validity_in_seconds = ceil(
            await original_implementation.get_access_token_lifetime_ms(user_context)
            / 1000
        )

        # Refresh session first because this will create a new access token
        new_session = await og_refresh_session(request, user_context)
        access_token_payload = new_session.get_access_token_payload()
        access_token_payload = await add_jwt_to_access_token_payload(
            access_token_payload=access_token_payload,
            jwt_expiry=get_jwt_expiry(access_token_validity_in_seconds),
            user_id=new_session.get_user_id(),
            jwt_property_name=config.jwt.property_name_in_access_token_payload,
            openid_recipe_implementation=openid_recipe_implementation,
            user_context=user_context,
        )

        await new_session.update_access_token_payload(
            access_token_payload, user_context
        )
        return get_session_with_jwt(new_session, openid_recipe_implementation)

    og_update_access_token_payload = original_implementation.update_access_token_payload

    async def jwt_aware_update_access_token_payload(
        session_information: SessionInformationResult,
        new_access_token_payload: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> bool:
        access_token_payload = session_information.access_token_payload

        if ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY not in access_token_payload:
            return await og_update_access_token_payload(
                session_information.session_handle,
                new_access_token_payload,
                user_context,
            )

        existing_jwt_property_name = access_token_payload[
            ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY
        ]

        assert existing_jwt_property_name in access_token_payload
        existing_jwt = access_token_payload[existing_jwt_property_name]

        current_time_in_seconds = ceil(get_timestamp_ms() / 1000)
        decoded_payload: Dict[str, Any] = decode(
            jwt=existing_jwt, options={"verify_signature": False, "verify_exp": False}
        )

        if decoded_payload is None:
            raise Exception("Error reading JWT from session")

        jwt_expiry = 1
        if "exp" in decoded_payload:
            exp = decoded_payload["exp"]
            if exp > current_time_in_seconds:
                # it can come here if someone calls this function well after
                # the access token and the jwt payload have expired. In this case,
                # we still want the jwt payload to update, but the resulting JWT should
                # not be alive for too long (since it's expired already). So we set it to
                # 1 second lifetime.
                jwt_expiry = exp - current_time_in_seconds

        new_access_token_payload = await add_jwt_to_access_token_payload(
            access_token_payload=new_access_token_payload,
            jwt_expiry=jwt_expiry,
            user_id=session_information.user_id,
            jwt_property_name=existing_jwt_property_name,
            openid_recipe_implementation=openid_recipe_implementation,
            user_context=user_context,
        )

        return await og_update_access_token_payload(
            session_information.session_handle, new_access_token_payload, user_context
        )

    async def update_access_token_payload(
        session_handle: str,
        new_access_token_payload: Optional[Dict[str, Any]],
        user_context: Dict[str, Any],
    ) -> bool:
        if new_access_token_payload is None:
            new_access_token_payload = {}

        session_information = await original_implementation.get_session_information(
            session_handle, user_context
        )
        if session_information is None:
            return False

        return await jwt_aware_update_access_token_payload(
            session_information, new_access_token_payload, user_context
        )

    async def merge_into_access_token_payload(
        session_handle: str,
        access_token_payload_update: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> bool:
        session_information = await original_implementation.get_session_information(
            session_handle, user_context
        )
        if session_information is None:
            return False

        new_access_token_payload = {
            **session_information.access_token_payload,
            **access_token_payload_update,
        }
        for k in access_token_payload_update.keys():
            if new_access_token_payload[k] is None:
                del new_access_token_payload[k]

        return await jwt_aware_update_access_token_payload(
            session_information, new_access_token_payload, user_context
        )

    original_implementation.create_new_session = create_new_session
    original_implementation.get_session = get_session
    original_implementation.refresh_session = refresh_session
    original_implementation.update_access_token_payload = update_access_token_payload
    original_implementation.merge_into_access_token_payload = (
        merge_into_access_token_payload
    )
    return original_implementation
