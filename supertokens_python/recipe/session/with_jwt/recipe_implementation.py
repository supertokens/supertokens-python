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

from typing import Union, TYPE_CHECKING

from jwt import decode

from supertokens_python.querier import Querier
from supertokens_python.utils import get_timestamp_ms
from .constants import ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY
from .session_class import get_session_with_jwt
from supertokens_python.recipe.session.recipe_implementation import RecipeImplementation
from .utills import add_jwt_to_access_token_payload
from supertokens_python.recipe.session import Session
if TYPE_CHECKING:
    from supertokens_python.recipe.session.utils import SessionConfig
from math import ceil
from supertokens_python.recipe.openid.interfaces import RecipeInterface as OpenIdRecipeInterface

EXPIRY_OFFSET_SECONDS = 30


def get_jwt_expiry(access_token_expiry: int):
    return access_token_expiry + EXPIRY_OFFSET_SECONDS


class RecipeImplementationWithJWT(RecipeImplementation):
    def __init__(self, querier: Querier, config: SessionConfig, openid_recipe_implementation: OpenIdRecipeInterface):
        super().__init__(querier, config)
        self.openid_recipe_implementation = openid_recipe_implementation

    async def create_new_session(self, request: any, user_id: str, access_token_payload: Union[dict, None] = None,
                                 session_data: Union[dict, None] = None) -> Session:
        if access_token_payload is None:
            access_token_payload = {}
        access_token_validity_in_seconds = ceil(await self.get_access_token_lifetime_ms() / 1000)
        access_token_payload = await add_jwt_to_access_token_payload(
            access_token_payload=access_token_payload,
            jwt_expiry=get_jwt_expiry(access_token_validity_in_seconds),
            user_id=user_id,
            jwt_property_name=self.config.jwt.property_name_in_access_token_payload,
            openid_recipe_implementation=self.openid_recipe_implementation
        )
        session = await RecipeImplementation.create_new_session(
            self, request, user_id, access_token_payload, session_data)
        return get_session_with_jwt(session, self.openid_recipe_implementation)

    async def get_session(self, request: any, anti_csrf_check: Union[bool, None] = None,
                          session_required: bool = True) -> Union[Session, None]:
        session_container = await RecipeImplementation.get_session(self, request, anti_csrf_check, session_required)
        if session_container is None:
            return None
        return get_session_with_jwt(session_container, self.openid_recipe_implementation)

    async def refresh_session(self, request: any) -> Session:
        access_token_validity_in_seconds = ceil(await self.get_access_token_lifetime_ms() / 1000)

        # Refresh session first because this will create a new access token
        new_session = await RecipeImplementation.refresh_session(self, request)
        access_token_payload = new_session.get_access_token_payload()
        access_token_payload = await add_jwt_to_access_token_payload(
            access_token_payload=access_token_payload,
            jwt_expiry=get_jwt_expiry(access_token_validity_in_seconds),
            user_id=new_session.get_user_id(),
            jwt_property_name=self.config.jwt.property_name_in_access_token_payload,
            openid_recipe_implementation=self.openid_recipe_implementation
        )

        await new_session.update_access_token_payload(access_token_payload)
        return get_session_with_jwt(new_session, self.openid_recipe_implementation)

    async def update_access_token_payload(self, session_handle: str, new_access_token_payload: dict) -> None:
        if new_access_token_payload is None:
            new_access_token_payload = {}
        session_information = await self.get_session_information(session_handle)
        access_token_payload = session_information['accessTokenPayload']

        if ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY not in access_token_payload:
            return await RecipeImplementation.update_access_token_payload(self, session_handle, new_access_token_payload)

        existing_jwt_property_name = access_token_payload[ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY]

        assert existing_jwt_property_name in access_token_payload
        existing_jwt = access_token_payload[existing_jwt_property_name]

        current_time_in_seconds = ceil(get_timestamp_ms() / 1000)
        decoded_payload = decode(jwt=existing_jwt, options={'verify_signature': False, 'verify_exp': False})

        if decoded_payload is None:
            raise Exception('Error reading JWT from session')

        jwt_expiry = 1
        if 'exp' in decoded_payload:
            exp = decoded_payload['exp']
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
            user_id=session_information['userId'],
            jwt_property_name=existing_jwt_property_name,
            openid_recipe_implementation=self.openid_recipe_implementation
        )

        return await RecipeImplementation.update_access_token_payload(self, session_handle, new_access_token_payload)
