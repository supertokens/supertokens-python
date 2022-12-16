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
from functools import wraps
from typing import Any, Callable, Dict, TypeVar, Union, cast, List, Optional

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.framework.flask.flask_request import FlaskRequest
from supertokens_python.recipe.session import SessionRecipe, SessionContainer
from supertokens_python.recipe.session.interfaces import SessionClaimValidator
from supertokens_python.types import MaybeAwaitable

_T = TypeVar("_T", bound=Callable[..., Any])


def verify_session(
    anti_csrf_check: Union[bool, None] = None,
    session_required: bool = True,
    override_global_claim_validators: Optional[
        Callable[
            [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Callable[[_T], _T]:
    if user_context is None:
        user_context = {}

    def session_verify(f: _T) -> _T:
        @wraps(f)
        def wrapped_function(*args: Any, **kwargs: Any):
            from flask import make_response, request

            baseRequest = FlaskRequest(request)
            recipe = SessionRecipe.get_instance()
            session = sync(
                recipe.verify_session(
                    baseRequest,
                    anti_csrf_check,
                    session_required,
                    override_global_claim_validators,
                    user_context,
                )
            )
            if session is None:
                if session_required:
                    raise Exception("Should never come here")
                baseRequest.set_session_as_none()
            else:
                baseRequest.set_session(session)
            response = make_response(f(*args, **kwargs))
            return response

        return cast(_T, wrapped_function)

    return session_verify
