from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, Any

from litestar.response.base import ASGIResponse

if TYPE_CHECKING:
    from litestar.middleware.base import AbstractMiddleware


@lru_cache
def get_middleware() -> type[AbstractMiddleware]:
    from supertokens_python import Supertokens
    from supertokens_python.exceptions import SuperTokensError
    from supertokens_python.framework.litestar.litestar_request import LitestarRequest
    from supertokens_python.framework.litestar.litestar_response import LitestarResponse
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.supertokens import manage_session_post_response
    from supertokens_python.utils import default_user_context

    from litestar import Response, Request
    from litestar.middleware.base import AbstractMiddleware
    from litestar.types import Scope, Receive, Send

    class SupertokensMiddleware(AbstractMiddleware):
        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            st = Supertokens.get_instance()
            request = Request[Any, Any, Any](scope, receive, send)
            user_context = default_user_context(request)

            try:
                result = await st.middleware(
                    LitestarRequest(request),
                    LitestarResponse(Response[Any](content=None)),
                    user_context
                )
            except SuperTokensError as e:
                result = await st.handle_supertokens_error(
                    LitestarRequest(request),
                    e,
                    LitestarResponse(Response[Any](content=None)),
                    user_context
                )

            if isinstance(result, LitestarResponse):
                if (
                    session_container := request.state.get("supertokens")
                ) and isinstance(session_container, SessionContainer):
                    manage_session_post_response(session_container, result, user_context)

                await result.response.to_asgi_response(app=None, request=request)(scope, receive, send)
                return

            await self.app(scope, receive, send)

    return SupertokensMiddleware
