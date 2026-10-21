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
import asyncio
from typing import Any, Dict, Type, Union

from litestar import Request, Response

from supertokens_python.exceptions import SuperTokensError


def supertokens_exception_handler(
    request: Request[Any, Any, Any], exc: SuperTokensError
) -> Response[Any]:
    """
    Exception handler for SuperTokens errors in Litestar applications.

    This handler intercepts SuperTokens exceptions and converts them to proper
    HTTP responses with session management.

    Note: This is a synchronous wrapper around async SuperTokens error handling.
    Litestar requires exception handlers to be synchronous, so we run the async
    logic in the event loop.

    Args:
            request: The Litestar request object
            exc: The SuperTokens exception

    Returns:
            A Litestar Response object with proper status code and session cookies
    """
    from supertokens_python import Supertokens
    from supertokens_python.framework.litestar.litestar_request import LitestarRequest
    from supertokens_python.framework.litestar.litestar_response import LitestarResponse
    from supertokens_python.utils import default_user_context

    async def handle_async() -> Response[Any]:
        """Async logic for handling the SuperTokens error"""
        st = Supertokens.get_instance()
        custom_request = LitestarRequest(request)
        user_context = default_user_context(custom_request)

        # Create a response for SuperTokens to populate
        response_obj = Response(content=None)
        response = LitestarResponse(response_obj)

        # Handle the error through SuperTokens
        # This will modify the response object with proper status code,
        # clear tokens, and set appropriate headers
        result = await st.handle_supertokens_error(
            custom_request,
            exc,
            response,
            user_context,
        )

        # Return the modified Litestar response
        # The response object has been updated by SuperTokens error handlers
        if isinstance(result, LitestarResponse):
            litestar_response = result.response

            # Clear the session from request.state to prevent the middleware
            # from re-applying session cookies after we've cleared them
            if hasattr(request.state, "supertokens"):
                delattr(request.state, "supertokens")

            # Litestar stores cookies separately from headers. When an exception
            # handler returns a response, Litestar will automatically convert cookies
            # to Set-Cookie headers. So we can just return the response as-is.
            return litestar_response

        # Fallback to a generic error response
        return Response(
            content={"message": str(exc)},
            status_code=500,
        )

    # Run the async logic in the event loop
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No event loop running, create one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(handle_async())
        finally:
            loop.close()
    else:
        # Event loop is already running (which is the case in Litestar)
        # Create a task and run it
        import nest_asyncio  # type: ignore

        nest_asyncio.apply()  # type: ignore
        return loop.run_until_complete(handle_async())


def get_exception_handlers() -> Dict[Union[int, Type[Exception]], Any]:
    """
    Get exception handlers for SuperTokens errors.

    Returns:
            A dictionary mapping exception types to handler functions.

    Example:
            ```python
            from litestar import Litestar
            from supertokens_python.framework.litestar import (
                    get_exception_handlers,
                    get_supertokens_plugin,
                    create_supertokens_middleware,
            )

            app = Litestar(
                    route_handlers=[...],
                    middleware=[create_supertokens_middleware()],
                    plugins=[get_supertokens_plugin(api_base_path="/auth")],
                    exception_handlers=get_exception_handlers(),
            )
            ```
    """
    return {SuperTokensError: supertokens_exception_handler}  # type: ignore
