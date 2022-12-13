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
from supertokens_python.recipe.session.interfaces import (
    APIInterface,
    SessionClaimValidator,
    SignOutOkayResponse,
)
from supertokens_python.types import MaybeAwaitable
from supertokens_python.utils import normalise_http_method

from ..utils import get_required_claim_validators

if TYPE_CHECKING:
    from supertokens_python.recipe.session.interfaces import APIOptions
    from ..interfaces import SessionContainer

from typing import Any, Dict


class APIImplementation(APIInterface):
    async def refresh_post(
        self, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> SessionContainer:
        return await api_options.recipe_implementation.refresh_session(
            api_options.request, user_context
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
            return None
        incoming_path = NormalisedURLPath(api_options.request.get_path())
        refresh_token_path = api_options.config.refresh_token_path
        if incoming_path.equals(refresh_token_path) and method == "post":
            return await api_options.recipe_implementation.refresh_session(
                api_options.request, user_context
            )
        session = await api_options.recipe_implementation.get_session(
            api_options.request,
            anti_csrf_check,
            session_required,
            user_context,
        )

        if session is not None:
            claim_validators = await get_required_claim_validators(
                session,
                override_global_claim_validators,
                user_context,
            )
            await session.assert_claims(claim_validators, user_context)

        return session
