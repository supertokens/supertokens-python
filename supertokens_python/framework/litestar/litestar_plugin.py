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
from typing import Union

from litestar import asgi
from litestar.config.app import AppConfig
from litestar.plugins import InitPluginProtocol


class SupertokensPlugin(InitPluginProtocol):
    """
    Litestar plugin for SuperTokens integration.

    This plugin handles authentication routes by mounting a custom ASGI app
    that processes SuperTokens authentication requests.
    """

    def __init__(self, api_base_path: str = "/auth"):
        """
        Initialize the SuperTokens plugin.

        Args:
            api_base_path: The base path for SuperTokens API routes (default: "/auth")
        """
        self.api_base_path = api_base_path.rstrip("/")

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """
        Called during app initialization to register the SuperTokens ASGI app.

        Args:
            app_config: The Litestar application configuration

        Returns:
            The modified application configuration
        """
        from litestar import Request, Response
        from litestar.types import Receive, Scope, Send

        from supertokens_python import Supertokens
        from supertokens_python.exceptions import SuperTokensError
        from supertokens_python.framework.litestar.litestar_request import (
            LitestarRequest,
        )
        from supertokens_python.framework.litestar.litestar_response import (
            LitestarResponse,
        )
        from supertokens_python.recipe.session import SessionContainer
        from supertokens_python.supertokens import manage_session_post_response
        from supertokens_python.utils import default_user_context

        async def supertokens_asgi_app(
            scope: Scope, receive: Receive, send: Send
        ) -> None:
            """
            ASGI app that handles SuperTokens authentication requests.
            """
            if scope["type"] != "http":
                # Pass through non-HTTP requests
                not_found = Response(content=None, status_code=404)
                await not_found.to_asgi_response(app=None, request=None)(
                    scope, receive, send
                )  # type: ignore
                return

            st = Supertokens.get_instance()

            # Create Litestar request and wrap it for SuperTokens
            litestar_request = Request(scope, receive=receive, send=send)
            custom_request = LitestarRequest(litestar_request)
            user_context = default_user_context(custom_request)

            try:
                # Create a response object for SuperTokens to use
                litestar_response = Response(content=None)
                response = LitestarResponse(litestar_response)

                # Let SuperTokens middleware handle the request
                result: Union[LitestarResponse, None] = await st.middleware(
                    custom_request, response, user_context
                )

                if result is None:
                    # Request was not handled by SuperTokens
                    not_found_response = Response(content=None, status_code=404)
                    await not_found_response.to_asgi_response(app=None, request=None)(
                        scope, receive, send
                    )  # type: ignore
                    return

                # Handle session management
                if hasattr(litestar_request.state, "supertokens") and isinstance(
                    litestar_request.state.supertokens, SessionContainer
                ):
                    manage_session_post_response(
                        litestar_request.state.supertokens, result, user_context
                    )

                # Send the response
                if isinstance(result, LitestarResponse):
                    asgi_response = result.response.to_asgi_response(
                        app=None, request=None
                    )  # type: ignore
                    await asgi_response(scope, receive, send)
                    return

            except SuperTokensError as e:
                # Handle SuperTokens-specific errors
                error_response_obj = Response(content=None)
                error_response = LitestarResponse(error_response_obj)
                result = await st.handle_supertokens_error(
                    custom_request, e, error_response, user_context
                )

                if isinstance(result, LitestarResponse):
                    asgi_response = result.response.to_asgi_response(
                        app=None, request=None
                    )  # type: ignore
                    await asgi_response(scope, receive, send)
                    return

            # Fallback - this should not normally be reached
            fallback_response = Response(content=None, status_code=500)
            await fallback_response.to_asgi_response(app=None, request=None)(
                scope, receive, send
            )  # type: ignore

        # Mount the SuperTokens ASGI app to handle auth routes
        app_mount = asgi(self.api_base_path, is_mount=True)(supertokens_asgi_app)
        app_config.route_handlers.append(app_mount)

        return app_config


def get_supertokens_plugin(api_base_path: str = "/auth") -> SupertokensPlugin:
    """
    Get a configured SuperTokens plugin for Litestar.

    Args:
        api_base_path: The base path for SuperTokens API routes (default: "/auth")

    Returns:
        A configured SupertokensPlugin instance
    """
    return SupertokensPlugin(api_base_path=api_base_path)
