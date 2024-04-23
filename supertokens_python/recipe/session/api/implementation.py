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

from typing import TYPE_CHECKING, Callable, List, Optional, Union

from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe.session.cookie_and_header import (
    clear_session_cookies_from_older_cookie_domain,
    has_multiple_cookies_for_token_type,
)
from supertokens_python.recipe.session.interfaces import (
    APIInterface,
    SessionClaimValidator,
    SignOutOkayResponse,
)
from supertokens_python.types import MaybeAwaitable
from supertokens_python.utils import normalise_http_method

if TYPE_CHECKING:
    from supertokens_python.recipe.session.interfaces import APIOptions
    from ..interfaces import SessionContainer

from typing import Any, Dict

from ..session_request_functions import (
    get_session_from_request,
    refresh_session_in_request,
)


class APIImplementation(APIInterface):
    async def refresh_post(
        self, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> SessionContainer:

        # If a request has multiple session cookies and 'older_cookie_domain' is
        # unset, we can't identify the correct cookie for refreshing the session.
        # Using the wrong cookie can cause an infinite refresh loop. To avoid this,
        # we throw a 500 error asking the user to set 'older_cookie_domain'.
        if (
            has_multiple_cookies_for_token_type(api_options.request, "access")
            or has_multiple_cookies_for_token_type(api_options.request, "refresh")
        ) and api_options.config.older_cookie_domain is None:
            raise Exception(
                "The request contains multiple session cookies. This may happen if you've changed the 'cookie_domain' setting in your configuration. To clear tokens from the previous domain, set 'older_cookie_domain' in your config."
            )

        clear_session_cookies_from_older_cookie_domain(
            api_options.request, api_options.config, user_context
        )

        return await refresh_session_in_request(
            api_options.request,
            user_context,
            api_options.config,
            api_options.recipe_implementation,
        )

    async def signout_post(
        self,
        session: Optional[SessionContainer],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> SignOutOkayResponse:
        if session is not None:
            await session.revoke_session(user_context)
        return SignOutOkayResponse()

    async def verify_session(
        self,
        api_options: APIOptions,
        anti_csrf_check: Union[bool, None],
        session_required: bool,
        check_database: bool,
        override_global_claim_validators: Optional[
            Callable[
                [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
                MaybeAwaitable[List[SessionClaimValidator]],
            ]
        ],
        user_context: Dict[str, Any],
    ) -> Union[SessionContainer, None]:
        method = normalise_http_method(api_options.request.method())
        if method in ("options", "trace"):
            if session_required:
                raise Exception(f"verify_session cannot be used with {method} method")
            return None
        incoming_path = NormalisedURLPath(api_options.request.get_path())
        refresh_token_path = api_options.config.refresh_token_path

        if incoming_path.equals(refresh_token_path) and method == "post":
            return await refresh_session_in_request(
                api_options.request,
                user_context,
                api_options.config,
                api_options.recipe_implementation,
            )

        return await get_session_from_request(
            api_options.request,
            api_options.config,
            api_options.recipe_implementation,
            session_required=session_required,
            anti_csrf_check=anti_csrf_check,
            check_database=check_database,
            override_global_claim_validators=override_global_claim_validators,
            user_context=user_context,
        )
