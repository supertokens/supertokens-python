from typing import Any

from litestar import Request, Response
from litestar.datastructures import MutableScopeHeaders
from litestar.enums import ScopeType
from litestar.middleware import ASGIMiddleware
from litestar.types import ASGIApp, Message, Receive, Scope, Send
from supertokens_python import Supertokens
from supertokens_python.exceptions import SuperTokensError
from supertokens_python.framework.litestar.litestar_request import LitestarRequest
from supertokens_python.framework.litestar.litestar_response import LitestarResponse
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.supertokens import manage_session_post_response
from supertokens_python.utils import default_user_context


class LitestarMiddleware(ASGIMiddleware):
    scopes = (ScopeType.HTTP, ScopeType.ASGI)

    async def handle(
        self, scope: Scope, receive: Receive, send: Send, next_app: ASGIApp
    ) -> None:
        if scope["type"] != "http":
            await next_app(scope, receive, send)
            return

        # Initialize SuperTokens and request/response objects
        st = Supertokens.get_instance()
        request = Request[Any, Any, Any](scope, receive=receive, send=send)
        custom_request = LitestarRequest(request)
        user_context = default_user_context(custom_request)

        try:
            response = LitestarResponse(Response[Any](content=None))
            result = await st.middleware(custom_request, response, user_context)

            if result is not None:
                # SuperTokens handled the request
                if hasattr(request.state, "supertokens") and isinstance(
                    request.state.supertokens, SessionContainer
                ):
                    manage_session_post_response(
                        request.state.supertokens, result, user_context
                    )
                # Convert response to ASGI and add cookies to headers
                asgi_response = await result.response.to_asgi_response(
                    app=next_app, request=request
                )

                async def modified_send(message: Message):
                    if message["type"] == "http.response.start":
                        mutable_headers = MutableScopeHeaders(message)
                        for cookie in result.response.cookies:
                            cookie_value = cookie.to_header().split(": ", 1)[1]
                            mutable_headers.add("set-cookie", cookie_value)
                    await send(message)

                await asgi_response(scope, receive, modified_send)
            else:
                # SuperTokens didn’t handle the request; pass to next app with wrapped send
                async def send_wrapper(message: Message):
                    if message["type"] == "http.response.start":
                        if hasattr(request.state, "supertokens") and isinstance(
                            request.state.supertokens, SessionContainer
                        ):
                            temp_response = Response[Any](content=None)
                            temp_response.headers = MutableScopeHeaders(message)
                            litestar_response = LitestarResponse(temp_response)
                            manage_session_post_response(
                                request.state.supertokens,
                                litestar_response,
                                user_context,
                            )
                            mutable_headers = MutableScopeHeaders(message)
                            for cookie in litestar_response.response.cookies:
                                cookie_value = cookie.to_header().split(": ", 1)[1]
                                mutable_headers.add("set-cookie", cookie_value)
                    await send(message)

                await next_app(scope, receive, send_wrapper)

        except SuperTokensError as e:
            # Handle SuperTokens errors
            response = LitestarResponse(Response[Any](content=None))
            result = await st.handle_supertokens_error(
                custom_request, e, response, user_context
            )
            if isinstance(result, LitestarResponse):
                asgi_response = await result.response.to_asgi_response(
                    app=next_app, request=request
                )

                async def modified_send(message: Message):
                    if message["type"] == "http.response.start":
                        mutable_headers = MutableScopeHeaders(message)
                        for cookie in result.response.cookies:
                            cookie_value = cookie.to_header().split(": ", 1)[1]
                            mutable_headers.add("set-cookie", cookie_value)
                    await send(message)

                await asgi_response(scope, receive, modified_send)
            else:
                raise Exception("Unexpected error handling in SuperTokens middleware")
