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

from supertokens_python.recipe.openid.interfaces import RecipeInterface
from .constants import ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY


async def add_jwt_to_access_token_payload(access_token_payload: dict,
                                          jwt_expiry: int, user_id: str, jwt_property_name: str,
                                          openid_recipe_implementation: RecipeInterface):
    if ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY in access_token_payload:
        # If jwtPropertyName is not undefined it means that the JWT was added to the access token payload already
        existing_jwt_property_name = access_token_payload[ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY]

        # Delete the old JWT and the old property name
        if existing_jwt_property_name in access_token_payload:
            del access_token_payload[existing_jwt_property_name]
        del access_token_payload[ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY]

    # Create the JWT
    jwt_response = await openid_recipe_implementation.create_jwt({
        # We add our claims before the user provided ones so that if they use the same claims
        # then the final payload will use the values they provide
        'sub': user_id,
        **access_token_payload
    }, jwt_expiry)

    if jwt_response.status == 'UNSUPPORTED_ALGORITHM_ERROR':
        # Should never come here
        raise Exception('JWT Signing algorithm not supported')

    # Add the jwt and the property name to the access token payload
    # We add the JWT after the user defined keys because we want to make sure that it never
    # gets overwritten by a user defined key. Using the same key as the one configured (or defaulting)
    # for the JWT should be considered a dev error
    #
    # ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY indicates a reserved key used to determine the property name
    # with which the JWT is set, used to retrieve the JWT from the access token payload during refresh and
    # updateAccessTokenPayload
    #
    # Note: If the user has multiple overrides each with a unique propertyNameInAccessTokenPayload, the logic for
    # checking the existing JWT when refreshing the session or updating the access token payload will not work.
    # This is because even though the jwt itself would be created with unique property names, the _jwtPName value
    # would always be overwritten by the override that runs last and when retrieving the jwt using that key name
    # it cannot be guaranteed that the right JWT is returned. This case is considered to be a rare requirement
    # and we assume that users will not need multiple JWT representations of their access token payload.
    access_token_payload[jwt_property_name] = jwt_response.jwt
    access_token_payload[ACCESS_TOKEN_PAYLOAD_JWT_PROPERTY_NAME_KEY] = jwt_property_name

    return access_token_payload
