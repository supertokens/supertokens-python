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
import json

from typing import Any, Callable, Coroutine, Dict, Union, List, Optional

from supertokens_python import Supertokens
from supertokens_python.framework.fastapi.fastapi_request import FastApiRequest
from supertokens_python.framework.fastapi.fastapi_response import FastApiResponse
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.exceptions import SuperTokensError
from supertokens_python.types import MaybeAwaitable
from fastapi.responses import JSONResponse

from ...interfaces import SessionContainer, SessionClaimValidator
from supertokens_python.utils import (
    set_request_in_user_context_if_not_defined,
    default_user_context,
)

from fastapi import Request


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
) -> Callable[..., Coroutine[Any, Any, Union[SessionContainer, None]]]:
    _ = user_context

    async def func(request: Request) -> Union[SessionContainer, None]:
        nonlocal user_context
        base_req = FastApiRequest(request)
        user_context = set_request_in_user_context_if_not_defined(
            user_context, base_req
        )

        recipe = SessionRecipe.get_instance()
        session = await recipe.verify_session(
            base_req,
            anti_csrf_check,
            session_required,
            check_database,
            override_global_claim_validators,
            user_context,
        )
        if session is None:
            if session_required:
                raise Exception("Should never come here")
            base_req.set_session_as_none()
        else:
            base_req.set_session(session)
        return base_req.get_session()

    return func


async def session_exception_handler(
    request: Request, exc: SuperTokensError
) -> JSONResponse:
    """FastAPI exceptional handler for errors raised by Supertokens SDK when not using middleware

    Usage: `app.add_exception_handler(SuperTokensError, st_exception_handler)`
    """
    base_req = FastApiRequest(request)
    base_res = FastApiResponse(JSONResponse())
    user_context = default_user_context(base_req)
    result = await Supertokens.get_instance().handle_supertokens_error(
        base_req, exc, base_res, user_context
    )
    if isinstance(result, FastApiResponse):
        body = json.loads(result.response.body)
        return JSONResponse(body, status_code=result.response.status_code)

    raise Exception("Should never come here")
