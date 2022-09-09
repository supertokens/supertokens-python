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

from math import ceil
from typing import TYPE_CHECKING, Any, Dict, Union, Optional

from jwt import decode
from supertokens_python.recipe.session.with_jwt.constants import (
    ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY,
)
from supertokens_python.recipe.session.with_jwt.utills import (
    add_jwt_to_access_token_payload,
)
from supertokens_python.utils import get_timestamp_ms

if TYPE_CHECKING:
    from supertokens_python.recipe.openid.interfaces import (
        RecipeInterface as OpenIdRecipeInterface,
    )
    from supertokens_python.recipe.session.interfaces import SessionContainer


def get_session_with_jwt(
    original_session: SessionContainer,
    openid_recipe_implementation: OpenIdRecipeInterface,
) -> SessionContainer:
    original_update_access_token_payload = original_session.update_access_token_payload

    async def update_access_token_payload(
        new_access_token_payload: Optional[Dict[str, Any]],
        user_context: Union[None, Dict[str, Any]] = None,
    ) -> None:
        if user_context is None:
            user_context = {}
        if new_access_token_payload is None:
            new_access_token_payload = {}

        access_token_payload = original_session.get_access_token_payload()

        if ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY not in access_token_payload:
            return await original_update_access_token_payload(
                new_access_token_payload, user_context
            )

        jwt_property_name = access_token_payload[
            ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY
        ]

        assert jwt_property_name in access_token_payload
        existing_jwt = access_token_payload[jwt_property_name]

        current_time_in_seconds = ceil(get_timestamp_ms() / 1000)
        decoded_payload: Union[None, Dict[str, Any]] = decode(
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
            user_id=original_session.get_user_id(),
            jwt_property_name=jwt_property_name,
            openid_recipe_implementation=openid_recipe_implementation,
            user_context=user_context,
        )

        return await original_update_access_token_payload(
            new_access_token_payload, user_context
        )

    original_session.update_access_token_payload = update_access_token_payload
    return original_session
