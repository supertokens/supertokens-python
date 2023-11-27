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

from supertokens_python import Supertokens
from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.exceptions import SuperTokensError
from supertokens_python.framework.django.django_request import DjangoRequest
from supertokens_python.framework.django.django_response import DjangoResponse
from supertokens_python.recipe.session import SessionRecipe, SessionContainer
from supertokens_python.recipe.session.interfaces import SessionClaimValidator
from supertokens_python.utils import set_request_in_user_context_if_not_defined
from supertokens_python.types import MaybeAwaitable

_T = TypeVar("_T", bound=Callable[..., Any])


def verify_session(
    anti_csrf_check: Union[bool, None] = None,
    session_required: bool = True,
    check_database: bool = False,
    override_global_claim_validators: Optional[
        Callable[
            [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Callable[[_T], _T]:
    _ = user_context

    def session_verify(f: _T) -> _T:
        from django.http import HttpRequest

        @wraps(f)
        def wrapped_function(request: HttpRequest, *args: Any, **kwargs: Any):
            nonlocal user_context
            from django.http import JsonResponse

            baseRequest = DjangoRequest(request)
            try:
                user_context = set_request_in_user_context_if_not_defined(
                    user_context, baseRequest
                )

                recipe = SessionRecipe.get_instance()
                session = sync(
                    recipe.verify_session(
                        baseRequest,
                        anti_csrf_check,
                        session_required,
                        check_database,
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
                return f(baseRequest.request, *args, **kwargs)
            except SuperTokensError as e:
                response = DjangoResponse(JsonResponse({}))
                user_context = set_request_in_user_context_if_not_defined(
                    user_context, baseRequest
                )
                result = sync(
                    Supertokens.get_instance().handle_supertokens_error(
                        DjangoRequest(request), e, response, user_context
                    )
                )
                if isinstance(result, DjangoResponse):
                    return result.response
                raise Exception("Should never come here")

        return cast(_T, wrapped_function)

    return session_verify
