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
from typing import TYPE_CHECKING, Any, Dict, List, Union

from supertokens_python.recipe.session.interfaces import SessionInformationResult

from .access_token import get_info_from_access_token
from .jwt import get_payload_without_verifying

if TYPE_CHECKING:
    from .recipe_implementation import RecipeImplementation

from supertokens_python.logger import log_debug_message
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.process_state import AllowedProcessStates, ProcessState

from .exceptions import (
    TryRefreshTokenError,
    raise_token_theft_exception,
    raise_try_refresh_token_exception,
    raise_unauthorised_exception,
)


async def create_new_session(
    recipe_implementation: RecipeImplementation,
    user_id: str,
    access_token_payload: Union[None, Dict[str, Any]],
    session_data: Union[None, Dict[str, Any]],
):
    if session_data is None:
        session_data = {}
    if access_token_payload is None:
        access_token_payload = {}

    handshake_info = await recipe_implementation.get_handshake_info()
    enable_anti_csrf = handshake_info.anti_csrf == "VIA_TOKEN"
    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath("/recipe/session"),
        {
            "userId": user_id,
            "userDataInJWT": access_token_payload,
            "userDataInDatabase": session_data,
            "enableAntiCsrf": enable_anti_csrf,
        },
    )
    recipe_implementation.update_jwt_signing_public_key_info(
        response["jwtSigningPublicKeyList"],
        response["jwtSigningPublicKey"],
        response["jwtSigningPublicKeyExpiryTime"],
    )
    response.pop("status", None)
    response.pop("jwtSigningPublicKey", None)
    response.pop("jwtSigningPublicKeyExpiryTime", None)
    response.pop("jwtSigningPublicKeyList", None)

    return response


async def get_session(
    recipe_implementation: RecipeImplementation,
    access_token: str,
    anti_csrf_token: Union[str, None],
    do_anti_csrf_check: bool,
    contains_custom_header: bool,
) -> Dict[str, Any]:
    handshake_info = await recipe_implementation.get_handshake_info()
    access_token_info = None
    found_a_sign_key_that_is_older_than_the_access_token = False

    for key in handshake_info.get_jwt_signing_public_key_list():
        try:
            access_token_info = get_info_from_access_token(
                access_token,
                key["publicKey"],
                handshake_info.anti_csrf == "VIA_TOKEN" and do_anti_csrf_check,
            )

            found_a_sign_key_that_is_older_than_the_access_token = True

        except Exception as e:
            payload = None

            if e.__class__ != TryRefreshTokenError:
                raise e

            try:
                payload = get_payload_without_verifying(access_token)
            except BaseException:
                raise e

            if payload is None:
                raise e

            if not isinstance(payload["timeCreated"], int) or not isinstance(
                payload["expiryTime"], int
            ):
                raise e

            if payload["expiryTime"] < time.time():
                raise e

            if payload["timeCreated"] >= key["createdAt"]:
                found_a_sign_key_that_is_older_than_the_access_token = True
                break

    if not found_a_sign_key_that_is_older_than_the_access_token:
        log_debug_message(
            "getSession: Returning TRY_REFRESH_TOKEN because signing key in handshake info is not up to date."
        )
        raise_try_refresh_token_exception(
            "access token has expired. Please call the refresh API"
        )

    if handshake_info.anti_csrf == "VIA_TOKEN" and do_anti_csrf_check:
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

    elif handshake_info.anti_csrf == "VIA_CUSTOM_HEADER" and do_anti_csrf_check:
        if not contains_custom_header:
            log_debug_message(
                "getSession: Returning TRY_REFRESH_TOKEN because custom header (rid) was not passed"
            )
            raise_try_refresh_token_exception(
                "anti-csrf check failed. Please pass 'rid: \"anti-csrf\"' header in the request, or set doAntiCsrfCheck to false "
                "for this API"
            )

    if (
        access_token_info is not None
        and not handshake_info.access_token_blacklisting_enabled
        and access_token_info["parentRefreshTokenHash1"] is None
    ):
        return {
            "session": {
                "handle": access_token_info["sessionHandle"],
                "userId": access_token_info["userId"],
                "userDataInJWT": access_token_info["userData"],
            }
        }

    ProcessState.get_instance().add_state(
        AllowedProcessStates.CALLING_SERVICE_IN_VERIFY
    )

    data = {
        "accessToken": access_token,
        "doAntiCsrfCheck": do_anti_csrf_check,
        "enableAntiCsrf": handshake_info.anti_csrf == "VIA_TOKEN",
    }
    if anti_csrf_token is not None:
        data["antiCsrfToken"] = anti_csrf_token

    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath("/recipe/session/verify"), data
    )
    if response["status"] == "OK":
        recipe_implementation.update_jwt_signing_public_key_info(
            response["jwtSigningPublicKeyList"],
            response["jwtSigningPublicKey"],
            response["jwtSigningPublicKeyExpiryTime"],
        )
        response.pop("status", None)
        response.pop("jwtSigningPublicKey", None)
        response.pop("jwtSigningPublicKeyExpiryTime", None)
        response.pop("jwtSigningPublicKeyList", None)
        return response
    if response["status"] == "UNAUTHORISED":
        log_debug_message("getSession: Returning UNAUTHORISED because of core response")
        raise_unauthorised_exception(response["message"])
    if (
        response["jwtSigningPublicKeyList"] is not None
        or response["jwtSigningPublicKey"] is not None
        or response["jwtSigningPublicKeyExpiryTime"] is not None
    ):
        recipe_implementation.update_jwt_signing_public_key_info(
            response["jwtSigningPublicKeyList"],
            response["jwtSigningPublicKey"],
            response["jwtSigningPublicKeyExpiryTime"],
        )
    else:
        await recipe_implementation.get_handshake_info(True)

    log_debug_message(
        "getSession: Returning TRY_REFRESH_TOKEN because of core response"
    )
    raise_try_refresh_token_exception(response["message"])


async def refresh_session(
    recipe_implementation: RecipeImplementation,
    refresh_token: str,
    anti_csrf_token: Union[str, None],
    contains_custom_header: bool,
):
    handshake_info = await recipe_implementation.get_handshake_info()
    data = {
        "refreshToken": refresh_token,
        "enableAntiCsrf": handshake_info.anti_csrf == "VIA_TOKEN",
    }
    if anti_csrf_token is not None:
        data["antiCsrfToken"] = anti_csrf_token

    if handshake_info.anti_csrf == "VIA_CUSTOM_HEADER":
        if not contains_custom_header:
            log_debug_message(
                "refreshSession: Returning UNAUTHORISED because custom header (rid) was not passed"
            )
            raise_unauthorised_exception(
                "anti-csrf check failed. Please pass 'rid: \"session\"' header "
                "in the request.",
                False,
            )
    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath("/recipe/session/refresh"), data
    )
    if response["status"] == "OK":
        response.pop("status", None)
        return response
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
    recipe_implementation: RecipeImplementation, user_id: str
) -> List[str]:
    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath("/recipe/session/remove"), {"userId": user_id}
    )
    return response["sessionHandlesRevoked"]


async def get_all_session_handles_for_user(
    recipe_implementation: RecipeImplementation, user_id: str
) -> List[str]:
    response = await recipe_implementation.querier.send_get_request(
        NormalisedURLPath("/recipe/session/user"), {"userId": user_id}
    )
    return response["sessionHandles"]


async def revoke_session(
    recipe_implementation: RecipeImplementation, session_handle: str
) -> bool:
    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath("/recipe/session/remove"),
        {"sessionHandles": [session_handle]},
    )
    return len(response["sessionHandlesRevoked"]) == 1


async def revoke_multiple_sessions(
    recipe_implementation: RecipeImplementation, session_handles: List[str]
) -> List[str]:
    response = await recipe_implementation.querier.send_post_request(
        NormalisedURLPath("/recipe/session/remove"), {"sessionHandles": session_handles}
    )
    return response["sessionHandlesRevoked"]


async def update_session_data(
    recipe_implementation: RecipeImplementation,
    session_handle: str,
    new_session_data: Dict[str, Any],
) -> bool:
    response = await recipe_implementation.querier.send_put_request(
        NormalisedURLPath("/recipe/session/data"),
        {"sessionHandle": session_handle, "userDataInDatabase": new_session_data},
    )
    if response["status"] == "UNAUTHORISED":
        return False

    return True


async def update_access_token_payload(
    recipe_implementation: RecipeImplementation,
    session_handle: str,
    new_access_token_payload: Dict[str, Any],
) -> bool:
    response = await recipe_implementation.querier.send_put_request(
        NormalisedURLPath("/recipe/jwt/data"),
        {"sessionHandle": session_handle, "userDataInJWT": new_access_token_payload},
    )
    if response["status"] == "UNAUTHORISED":
        return False

    return True


async def get_session_information(
    recipe_implementation: RecipeImplementation, session_handle: str
) -> Union[SessionInformationResult, None]:
    response = await recipe_implementation.querier.send_get_request(
        NormalisedURLPath("/recipe/session"), {"sessionHandle": session_handle}
    )
    if response["status"] == "OK":
        return SessionInformationResult(
            response["sessionHandle"],
            response["userId"],
            response["userDataInDatabase"],
            response["expiry"],
            response["userDataInJWT"],
            response["timeCreated"],
        )
    return None
