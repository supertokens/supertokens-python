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
from typing import Any, Callable, Coroutine, Dict, Union, List, Optional

from supertokens_python.framework.fastapi.fastapi_request import FastApiRequest
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.types import MaybeAwaitable

from ...interfaces import SessionContainer, SessionClaimValidator


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
) -> Callable[..., Coroutine[Any, Any, Union[SessionContainer, None]]]:
    if user_context is None:
        user_context = {}
    from fastapi import Request

    async def func(request: Request) -> Union[SessionContainer, None]:
        baseRequest = FastApiRequest(request)
        recipe = SessionRecipe.get_instance()
        session = await recipe.verify_session(
            baseRequest,
            anti_csrf_check,
            session_required,
            override_global_claim_validators,
            user_context,
        )
        if session is None:
            if session_required:
                raise Exception("Should never come here")
            baseRequest.set_session_as_none()
        else:
            baseRequest.set_session(session)
        return baseRequest.get_session()

    return func
