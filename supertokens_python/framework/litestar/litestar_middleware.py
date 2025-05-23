from typing import Any

from litestar import Request, Response
from litestar.datastructures import MutableScopeHeaders
from litestar.middleware.base import AbstractMiddleware
from litestar.types import Message, Receive, Scope, Send
from supertokens_python import Supertokens
from supertokens_python.exceptions import SuperTokensError
from supertokens_python.framework.litestar.litestar_request import LitestarRequest
from supertokens_python.framework.litestar.litestar_response import LitestarResponse
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.supertokens import manage_session_post_response
from supertokens_python.utils import default_user_context


class LitestarMiddleware(AbstractMiddleware):
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

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
                # Add cookies using MutableScopeHeaders
                asgi_response = await result.response.to_asgi_response(
                    app=None, request=request
                )

                async def modified_send(message: Message):
                    if message["type"] == "http.response.start":
                        mutable_headers = MutableScopeHeaders(message)
                        for cookie in result.response.cookies:
                            cookie_value = cookie.to_header().split(": ", 1)[1]
                            mutable_headers.add("set-cookie", cookie_value)
                    await send(message)

                await asgi_response(scope, receive, modified_send)
                return
            else:
                # SuperTokens didn’t handle the request; wrap the send function
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

                await self.app(scope, receive, send_wrapper)
                return

        except SuperTokensError as e:
            response = LitestarResponse(Response[Any](content=None))
            result = await st.handle_supertokens_error(
                custom_request, e, response, user_context
            )
            if isinstance(result, LitestarResponse):
                # Add cookies using MutableScopeHeaders
                asgi_response = await result.response.to_asgi_response(
                    app=None, request=request
                )

                async def modified_send(message: Message):
                    if message["type"] == "http.response.start":
                        mutable_headers = MutableScopeHeaders(message)
                        for cookie in result.response.cookies:
                            cookie_value = cookie.to_header().split(": ", 1)[1]
                            mutable_headers.add("set-cookie", cookie_value)
                    await send(message)

                await asgi_response(scope, receive, modified_send)
                return
            raise Exception("Should never come here")
