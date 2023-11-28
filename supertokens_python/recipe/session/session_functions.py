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

import time
from typing import TYPE_CHECKING, Any, Dict, List, Union, Optional

from supertokens_python.recipe.session.interfaces import SessionInformationResult

from .access_token import get_info_from_access_token
from .constants import JWKCacheMaxAgeInMs
from .jwt import ParsedJWTInfo

if TYPE_CHECKING:
    from .recipe_implementation import RecipeImplementation

from supertokens_python.logger import log_debug_message
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.process_state import AllowedProcessStates, ProcessState
from supertokens_python.recipe.session.interfaces import TokenInfo

from .exceptions import (
    TryRefreshTokenError,
    raise_token_theft_exception,
    raise_try_refresh_token_exception,
    raise_unauthorised_exception,
)

from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID


class CreateOrRefreshAPIResponseSession:
    def __init__(self, handle: str, userId: str, userDataInJWT: Any, tenant_id: str):
        self.handle = handle
        self.userId = userId
        self.userDataInJWT = userDataInJWT
        self.tenant_id = tenant_id


class CreateOrRefreshAPIResponse:
    def __init__(
        self,
        session: CreateOrRefreshAPIResponseSession,
        accessToken: TokenInfo,
        refreshToken: TokenInfo,
        antiCsrfToken: Optional[str],
    ):
        self.session = session
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.antiCsrfToken = antiCsrfToken


class GetSessionAPIResponseSession:
    def __init__(
        self,
        handle: str,
        userId: str,
        userDataInJWT: Dict[str, Any],
        expiryTime: int,
        tenant_id: str,
    ) -> None:
        self.handle = handle
        self.userId = userId
        self.userDataInJWT = userDataInJWT
        self.expiryTime = expiryTime
        self.tenant_id = tenant_id


class GetSessionAPIResponseAccessToken:
    def __init__(self, token: str, expiry: int, createdTime: int) -> None:
        self.token = token
        self.expiry = expiry
        self.createdTime = createdTime


class GetSessionAPIResponse:
    def __init__(
        self,
        session: GetSessionAPIResponseSession,
        accessToken: Optional[GetSessionAPIResponseAccessToken] = None,
    ) -> None:
        self.session = session
        self.accessToken = accessToken


async def create_new_session(
    recipe_implementation: RecipeImplementation,
    tenant_id: str,
    user_id: str,
    disable_anti_csrf: bool,
    access_token_payload: Union[None, Dict[str, Any]],
    session_data_in_database: Union[None, Dict[str, Any]],
    user_context: Optional[Dict[str, Any]],
) -> CreateOrRefreshAPIResponse:
    if session_data_in_database is None:
        session_data_in_database = {}
    if access_token_payload is None:
        access_token_payload = {}
    enable_anti_csrf = (
        disable_anti_csrf is False
        # We dont need to check if anti csrf is a function here because checking for "VIA_TOKEN" is enough
        and recipe_implementation.config.anti_csrf_function_or_string == "VIA_TOKEN"
    )
    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath(f"{tenant_id}/recipe/session"),
        {
            "userId": user_id,
            "userDataInJWT": access_token_payload,
            "userDataInDatabase": session_data_in_database,
            "useDynamicSigningKey": recipe_implementation.config.use_dynamic_access_token_signing_key,
            "enableAntiCsrf": enable_anti_csrf,
        },
        user_context=user_context,
    )

    return CreateOrRefreshAPIResponse(
        CreateOrRefreshAPIResponseSession(
            response["session"]["handle"],
            response["session"]["userId"],
            response["session"]["userDataInJWT"],
            response["session"]["tenantId"],
        ),
        TokenInfo(
            response["accessToken"]["token"],
            response["accessToken"]["expiry"],
            response["accessToken"]["createdTime"],
        ),
        TokenInfo(
            response["refreshToken"]["token"],
            response["refreshToken"]["expiry"],
            response["refreshToken"]["createdTime"],
        ),
        response["antiCsrfToken"] if "antiCsrfToken" in response else None,
    )


async def get_session(
    recipe_implementation: RecipeImplementation,
    parsed_access_token: ParsedJWTInfo,
    anti_csrf_token: Union[str, None],
    do_anti_csrf_check: bool,
    always_check_core: bool,
    user_context: Optional[Dict[str, Any]],
) -> GetSessionAPIResponse:
    config = recipe_implementation.config
    access_token_info: Optional[Dict[str, Any]] = None

    try:
        access_token_info = get_info_from_access_token(
            parsed_access_token,
            config.anti_csrf_function_or_string == "VIA_TOKEN" and do_anti_csrf_check,
        )

    except Exception as e:
        if not isinstance(e, TryRefreshTokenError):
            raise e

        # if it comes here, it means token verification has failed.
        # It may be due to:
        # - signing key was updated and this token was signed with new key
        # - access token is actually expired
        # - access token was signed with the older signing key

        # if access token is actually expired, we don't need to call core and
        # just return TRY_REFRESH_TOKEN to the client

        # if access token creation time is after this signing key was created
        # we need to call core as there are chances that the token
        # was signed with the updated signing key

        # if access token creation time is before oldest signing key was created,
        # so if foundASigningKeyThatIsOlderThanTheAccessToken is still false after
        # the loop we just return TRY_REFRESH_TOKEN

        payload = parsed_access_token.payload

        time_created = payload.get("timeCreated")
        expiry_time = payload.get("expiryTime")

        if not isinstance(time_created, int) or not isinstance(expiry_time, int):
            raise e

        if parsed_access_token.version < 3:
            if expiry_time < time.time():
                raise e

            # We check if the token was created since the last time we refreshed the keys from the core
            # Since we do not know the exact timing of the last refresh, we check against the max age
            if time_created <= time.time() - JWKCacheMaxAgeInMs:
                raise e
        else:
            # Since v3 (and above) tokens contain a kid we can trust the cache refresh mechanism built on top of the pyjwt lib
            # This means we do not need to call the core since the signature wouldn't pass verification anyway.
            raise e

    if parsed_access_token.version >= 3:
        token_use_dynamic_key = (
            parsed_access_token.kid.startswith("d-")
            if parsed_access_token.kid is not None
            else False
        )

        if token_use_dynamic_key != config.use_dynamic_access_token_signing_key:
            log_debug_message(
                "getSession: Returning TRY_REFRESH_TOKEN because the access token doesn't match the useDynamicAccessTokenSigningKey in the config"
            )

            raise_try_refresh_token_exception(
                "The access token doesn't match the useDynamicAccessTokenSigningKey setting"
            )

    # If we get here we either have a V2 token that doesn't pass verification or a valid V3> token
    # anti-csrf check if accesstokenInfo is not undefined which means token verification was successful

    if do_anti_csrf_check:
        if config.anti_csrf_function_or_string == "VIA_TOKEN":
            if access_token_info is not None:
                if (
                    anti_csrf_token is None
                    or anti_csrf_token != access_token_info["antiCsrfToken"]
                ):
                    if anti_csrf_token is None:
                        log_debug_message(
                            "getSession: Returning TRY_REFRESH_TOKEN because antiCsrfToken is missing from request"
                        )
                        raise_try_refresh_token_exception(
                            "Provided antiCsrfToken is undefined. If you do not want anti-csrf check for this API, please set doAntiCsrfCheck to false for this API"
                        )
                    else:
                        log_debug_message(
                            "getSession: Returning TRY_REFRESH_TOKEN because the passed antiCsrfToken is not the same as in the access token"
                        )
                        raise_try_refresh_token_exception("anti-csrf check failed")

        elif (
            isinstance(config.anti_csrf_function_or_string, str)
            and config.anti_csrf_function_or_string == "VIA_CUSTOM_HEADER"
        ):
            # The function should never be called by this (we check this outside the function as well)
            # There we can add a bit more information to the error, so that's the primary check, this is just making sure.
            raise Exception(
                "Please either use VIA_TOKEN, NONE or call with doAntiCsrfCheck false"
            )

    if (
        access_token_info is not None
        and not always_check_core
        and access_token_info["parentRefreshTokenHash1"] is None
    ):
        return GetSessionAPIResponse(
            GetSessionAPIResponseSession(
                access_token_info["sessionHandle"],
                access_token_info["userId"],
                access_token_info["userData"],
                access_token_info["expiryTime"],
                access_token_info["tenantId"],
            )
        )

    ProcessState.get_instance().add_state(
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
    )

    data = {
        "accessToken": parsed_access_token.raw_token_string,
        "doAntiCsrfCheck": do_anti_csrf_check,
        "enableAntiCsrf": config.anti_csrf_function_or_string == "VIA_TOKEN",
        "checkDatabase": always_check_core,
    }
    if anti_csrf_token is not None:
        data["antiCsrfToken"] = anti_csrf_token

    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath("/recipe/session/verify"),
        data,
        user_context=user_context,
    )
    if response["status"] == "OK":
        return GetSessionAPIResponse(
            GetSessionAPIResponseSession(
                response["session"]["handle"],
                response["session"]["userId"],
                response["session"]["userDataInJWT"],
                (
                    response.get("accessToken", {}).get(
                        "expiry"
                    )  # if we got a new accesstoken we take the expiry time from there
                    or (
                        access_token_info is not None
                        and access_token_info.get("expiryTime")
                    )  # if we didn't get a new access token but could validate the token take that info (alwaysCheckCore === true, or parentRefreshTokenHash1 !== null)
                    or parsed_access_token.payload[
                        "expiryTime"
                    ]  # if the token didn't pass validation, but we got here, it means it was a v2 token that we didn't have the key cached for.
                ),  # This will throw error if others are none and 'expiryTime' key doesn't exist in the payload
                response["session"].get("tenantId")
                or (access_token_info or {}).get("tenantId"),
            ),
            GetSessionAPIResponseAccessToken(
                response["accessToken"]["token"],
                response["accessToken"]["expiry"],
                response["accessToken"]["createdTime"],
            )
            if "accessToken" in response
            else None,
        )
    if response["status"] == "UNAUTHORISED":
        log_debug_message("getSession: Returning UNAUTHORISED because of core response")
        raise_unauthorised_exception(response["message"])

    log_debug_message(
        "getSession: Returning TRY_REFRESH_TOKEN because of core response"
    )
    raise_try_refresh_token_exception(response["message"])


async def refresh_session(
    recipe_implementation: RecipeImplementation,
    refresh_token: str,
    anti_csrf_token: Union[str, None],
    disable_anti_csrf: bool,
    user_context: Optional[Dict[str, Any]],
) -> CreateOrRefreshAPIResponse:
    data = {
        "refreshToken": refresh_token,
        "enableAntiCsrf": (
            not disable_anti_csrf
            and recipe_implementation.config.anti_csrf_function_or_string == "VIA_TOKEN"
        ),
    }

    if anti_csrf_token is not None:
        data["antiCsrfToken"] = anti_csrf_token

    if (
        isinstance(recipe_implementation.config.anti_csrf_function_or_string, str)
        and recipe_implementation.config.anti_csrf_function_or_string
        == "VIA_CUSTOM_HEADER"
        and not disable_anti_csrf
    ):
        # The function should never be called by this (we check this outside the function as well)
        # There we can add a bit more information to the error, so that's the primary check, this is just making sure.
        raise Exception(
            "Please either use VIA_TOKEN, NONE or call with doAntiCsrfCheck false"
        )

    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath("/recipe/session/refresh"),
        data,
        user_context=user_context,
    )
    if response["status"] == "OK":
        return CreateOrRefreshAPIResponse(
            CreateOrRefreshAPIResponseSession(
                response["session"]["handle"],
                response["session"]["userId"],
                response["session"]["userDataInJWT"],
                response["session"]["tenantId"],
            ),
            TokenInfo(
                response["accessToken"]["token"],
                response["accessToken"]["expiry"],
                response["accessToken"]["createdTime"],
            ),
            TokenInfo(
                response["refreshToken"]["token"],
                response["refreshToken"]["expiry"],
                response["refreshToken"]["createdTime"],
            ),
            response["antiCsrfToken"] if "antiCsrfToken" in response else None,
        )
    if response["status"] == "UNAUTHORISED":
        log_debug_message(
            "refreshSession: Returning UNAUTHORISED because of core response"
        )
        raise_unauthorised_exception(response["message"])
    log_debug_message(
        "refreshSession: Returning TOKEN_THEFT_DETECTED because of core response"
    )
    raise_token_theft_exception(
        response["session"]["userId"], response["session"]["handle"]
    )


async def revoke_all_sessions_for_user(
    recipe_implementation: RecipeImplementation,
    user_id: str,
    tenant_id: Optional[str],
    revoke_across_all_tenants: bool,
    user_context: Optional[Dict[str, Any]],
) -> List[str]:
    if tenant_id is None:
        tenant_id = DEFAULT_TENANT_ID

    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath(f"{tenant_id}/recipe/session/remove"),
        {"userId": user_id, "revokeAcrossAllTenants": revoke_across_all_tenants},
        user_context=user_context,
    )
    return response["sessionHandlesRevoked"]


async def get_all_session_handles_for_user(
    recipe_implementation: RecipeImplementation,
    user_id: str,
    tenant_id: Optional[str],
    fetch_across_all_tenants: bool,
    user_context: Optional[Dict[str, Any]],
) -> List[str]:
    if tenant_id is None:
        tenant_id = DEFAULT_TENANT_ID

    response = await recipe_implementation.querier.send_get_request(
        NormalisedURLPath(f"{tenant_id}/recipe/session/user"),
        {"userId": user_id, "fetchAcrossAllTenants": fetch_across_all_tenants},
        user_context=user_context,
    )
    return response["sessionHandles"]


async def revoke_session(
    recipe_implementation: RecipeImplementation,
    session_handle: str,
    user_context: Optional[Dict[str, Any]],
) -> bool:
    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath("/recipe/session/remove"),
        {"sessionHandles": [session_handle]},
        user_context=user_context,
    )
    return len(response["sessionHandlesRevoked"]) == 1


async def revoke_multiple_sessions(
    recipe_implementation: RecipeImplementation,
    session_handles: List[str],
    user_context: Optional[Dict[str, Any]],
) -> List[str]:
    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath("/recipe/session/remove"),
        {"sessionHandles": session_handles},
        user_context=user_context,
    )
    return response["sessionHandlesRevoked"]


async def update_session_data_in_database(
    recipe_implementation: RecipeImplementation,
    session_handle: str,
    new_session_data: Dict[str, Any],
    user_context: Optional[Dict[str, Any]],
) -> bool:
    response = await recipe_implementation.querier.send_put_request(
        NormalisedURLPath("/recipe/session/data"),
        {"sessionHandle": session_handle, "userDataInDatabase": new_session_data},
        user_context=user_context,
    )
    if response["status"] == "UNAUTHORISED":
        return False

    return True


async def update_access_token_payload(
    recipe_implementation: RecipeImplementation,
    session_handle: str,
    new_access_token_payload: Dict[str, Any],
    user_context: Optional[Dict[str, Any]],
) -> bool:
    response = await recipe_implementation.querier.send_put_request(
        NormalisedURLPath("/recipe/jwt/data"),
        {"sessionHandle": session_handle, "userDataInJWT": new_access_token_payload},
        user_context=user_context,
    )
    if response["status"] == "UNAUTHORISED":
        return False

    return True


async def get_session_information(
    recipe_implementation: RecipeImplementation,
    session_handle: str,
    user_context: Optional[Dict[str, Any]],
) -> Union[SessionInformationResult, None]:
    response = await recipe_implementation.querier.send_get_request(
        NormalisedURLPath("/recipe/session"),
        {"sessionHandle": session_handle},
        user_context=user_context,
    )
    if response["status"] == "OK":
        return SessionInformationResult(
            response["sessionHandle"],
            response["userId"],
            response["userDataInDatabase"],
            response["expiry"],
            response["userDataInJWT"],
            response["timeCreated"],
            response["tenantId"],
        )
    return None
