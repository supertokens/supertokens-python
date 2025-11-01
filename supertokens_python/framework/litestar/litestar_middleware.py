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
from litestar.middleware import DefineMiddleware
from litestar.types import ASGIApp, Receive, Scope, Send


class SupertokensSessionMiddleware:
    """
    Middleware to handle session management for non-auth routes.

    This middleware applies session-related response mutators (like setting cookies)
    for routes that use SuperTokens sessions but aren't auth routes.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        from litestar import Request
        from litestar import Response as LitestarResponseObj
        from litestar.types import Message

        from supertokens_python.framework.litestar.litestar_request import (
            LitestarRequest,
        )
        from supertokens_python.framework.litestar.litestar_response import (
            LitestarResponse,
        )
        from supertokens_python.recipe.session import SessionContainer
        from supertokens_python.supertokens import manage_session_post_response
        from supertokens_python.utils import default_user_context

        request = Request(scope, receive=receive, send=send)  # type: ignore
        custom_request = LitestarRequest(request)
        user_context = default_user_context(custom_request)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                # Apply session mutators to response headers
                if hasattr(request.state, "supertokens") and isinstance(
                    getattr(request.state, "supertokens", None), SessionContainer
                ):
                    # Create a temporary Litestar Response
                    temp_response = LitestarResponseObj(content=None)

                    # Convert raw ASGI headers to dict for Litestar Response
                    for name, value in message.get("headers", []):  # type: ignore
                        temp_response.headers[
                            name.decode() if isinstance(name, bytes) else name
                        ] = value.decode() if isinstance(value, bytes) else value

                    # Wrap it for SuperTokens
                    wrapped_response = LitestarResponse(temp_response)

                    # Apply session mutators (this will modify temp_response)
                    manage_session_post_response(
                        getattr(request.state, "supertokens"),
                        wrapped_response,
                        user_context,
                    )

                    # Convert the Litestar Response to ASGI format to get cookies as Set-Cookie headers
                    asgi_response = temp_response.to_asgi_response(
                        app=None, request=None
                    )  # type: ignore

                    # Use the encoded headers which include Set-Cookie headers from cookies
                    message["headers"] = asgi_response.encoded_headers

            await send(message)

        await self.app(scope, receive, send_wrapper)


def create_supertokens_middleware() -> DefineMiddleware:
    """
    Create a DefineMiddleware instance for SuperTokens session management.

    Returns:
        A DefineMiddleware configured with SupertokensSessionMiddleware
    """
    return DefineMiddleware(SupertokensSessionMiddleware)
