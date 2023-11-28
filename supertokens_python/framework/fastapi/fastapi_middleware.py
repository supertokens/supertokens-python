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

from typing import TYPE_CHECKING, Union

from supertokens_python.framework import BaseResponse

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def get_middleware():
    from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
    from supertokens_python.utils import default_user_context

    class Middleware(BaseHTTPMiddleware):
        def __init__(self, app: FastAPI):
            super().__init__(app)

        async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
            from supertokens_python import Supertokens
            from supertokens_python.exceptions import SuperTokensError
            from supertokens_python.framework.fastapi.fastapi_request import (
                FastApiRequest,
            )
            from supertokens_python.framework.fastapi.fastapi_response import (
                FastApiResponse,
            )
            from supertokens_python.recipe.session import SessionContainer
            from supertokens_python.supertokens import manage_session_post_response

            st = Supertokens.get_instance()
            from fastapi.responses import Response

            custom_request = FastApiRequest(request)
            response = FastApiResponse(Response())
            user_context = default_user_context(custom_request)

            try:
                result: Union[BaseResponse, None] = await st.middleware(
                    custom_request, response, user_context
                )
                if result is None:
                    response = await call_next(request)
                    result = FastApiResponse(response)

                if hasattr(request.state, "supertokens") and isinstance(
                    request.state.supertokens, SessionContainer
                ):
                    manage_session_post_response(
                        request.state.supertokens, result, user_context
                    )
                if isinstance(result, FastApiResponse):
                    return result.response
            except SuperTokensError as e:
                response = FastApiResponse(Response())
                result: Union[BaseResponse, None] = await st.handle_supertokens_error(
                    FastApiRequest(request), e, response, user_context
                )
                if isinstance(result, FastApiResponse):
                    return result.response

            raise Exception("Should never come here")

    return Middleware
