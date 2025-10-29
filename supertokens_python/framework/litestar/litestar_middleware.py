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
from typing import Any, Union, cast


def get_middleware():
    from litestar import Request as LitestarRequestClass
    from litestar import Response as LitestarResponseClass
    from starlette.responses import Response as StarletteResponse
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from supertokens_python import Supertokens
    from supertokens_python.exceptions import SuperTokensError
    from supertokens_python.framework import BaseResponse
    from supertokens_python.framework.litestar.litestar_request import (
        LitestarRequest,
    )
    from supertokens_python.framework.litestar.litestar_response import (
        LitestarResponse,
    )
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.supertokens import manage_session_post_response
    from supertokens_python.utils import default_user_context

    class ASGIMiddleware:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] != "http":
                await self.app(scope, receive, send)
                return

            st = Supertokens.get_instance()

            request = LitestarRequestClass[Any, Any, Any](
                cast(Any, scope), receive=cast(Any, receive)
            )
            custom_request = LitestarRequest(request)
            user_context = default_user_context(custom_request)

            try:
                response = LitestarResponse(LitestarResponseClass[Any](content={}))
                result: Union[BaseResponse, None] = await st.middleware(
                    custom_request, response, user_context
                )
                if result is None:

                    async def send_wrapper(message: Message):
                        if message["type"] == "http.response.start":
                            if hasattr(request.state, "supertokens") and isinstance(
                                request.state.supertokens, SessionContainer
                            ):
                                starlette_response = StarletteResponse()
                                starlette_response.raw_headers = message["headers"]
                                response = LitestarResponse(
                                    cast(LitestarResponseClass[Any], starlette_response)
                                )
                                manage_session_post_response(
                                    request.state.supertokens, response, user_context
                                )
                                message["headers"] = starlette_response.raw_headers

                        await send(message)

                    await self.app(scope, receive, send_wrapper)
                    return

                if hasattr(request.state, "supertokens") and isinstance(
                    request.state.supertokens, SessionContainer
                ):
                    manage_session_post_response(
                        request.state.supertokens, result, user_context
                    )

                if isinstance(result, LitestarResponse):
                    resp_any = cast(Any, result.response)
                    asgi_response = resp_any.to_asgi_response(app=None, request=request)
                    await asgi_response(scope, receive, send)
                    return

                return

            except SuperTokensError as e:
                response = LitestarResponse(LitestarResponseClass[Any](content={}))
                result: Union[BaseResponse, None] = await st.handle_supertokens_error(
                    LitestarRequest(request), e, response, user_context
                )
                if isinstance(result, LitestarResponse):
                    resp_any = cast(Any, result.response)
                    asgi_response = resp_any.to_asgi_response(app=None, request=request)
                    await asgi_response(scope, receive, send)
                    return

                async def send_wrapper(message: Message):
                    if message["type"] == "http.response.start":
                        if hasattr(request.state, "supertokens") and isinstance(
                            request.state.supertokens, SessionContainer
                        ):
                            starlette_response = StarletteResponse()
                            starlette_response.raw_headers = message["headers"]
                            response = LitestarResponse(
                                cast(LitestarResponseClass[Any], starlette_response)
                            )
                            manage_session_post_response(
                                request.state.supertokens, response, user_context
                            )
                            message["headers"] = starlette_response.raw_headers
                    await send(message)

                await self.app(scope, receive, send_wrapper)

    return ASGIMiddleware
