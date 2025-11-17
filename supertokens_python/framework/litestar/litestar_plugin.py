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

from typing import Union, cast

from litestar import asgi
from litestar.config.app import AppConfig
from litestar.plugins import InitPluginProtocol


class SupertokensPlugin(InitPluginProtocol):
    """
    Litestar plugin for SuperTokens integration.

    This plugin handles authentication routes by mounting a custom ASGI app
    that processes SuperTokens authentication requests.
    """

    def __init__(self, mount_path: str = "/auth"):
        """
        Initialize the SuperTokens plugin.

        Args:
                mount_path: The path where the SuperTokens ASGI app will be mounted.
                           This is the external path that will be accessible (e.g., "/auth" or "/api/v1/auth").
        """
        # Normalize the mount path
        self.mount_path = mount_path.rstrip("/") or "/"
        if not self.mount_path.startswith("/"):
            self.mount_path = f"/{self.mount_path}"

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
                not_found = Response(content=None, status_code=404)
                await not_found.to_asgi_response(  # type: ignore
                    app=None, request=Request(scope, receive, send)
                )(scope, receive, send)
                return

            st = Supertokens.get_instance()

            # Create Litestar request and wrap it for SuperTokens
            litestar_request = Request(scope, receive=receive, send=send)  # type: ignore
            custom_request = LitestarRequest(litestar_request)  # type: ignore
            user_context = default_user_context(custom_request)

            try:
                # Create a response object for SuperTokens to use
                litestar_response = Response(content=None)
                response = LitestarResponse(litestar_response)

                # Let SuperTokens handle the request
                handled: Union[LitestarResponse, None] = cast(
                    LitestarResponse,
                    await st.middleware(custom_request, response, user_context),
                )

                if handled is None:  # type: ignore
                    not_found = Response(content=None, status_code=404)
                    await not_found.to_asgi_response(
                        app=None, request=Request(scope, receive, send)
                    )(scope, receive, send)
                    return

                # Handle session management
                if hasattr(litestar_request.state, "supertokens") and isinstance(  # type: ignore
                    litestar_request.state.supertokens,  # type: ignore
                    SessionContainer,
                ):
                    manage_session_post_response(
                        litestar_request.state.supertokens,  # type: ignore
                        handled,
                        user_context,
                    )

                # Emit response
                asgi_response = handled.response.to_asgi_response(  # type: ignore
                    app=None, request=Request(scope, receive, send)
                )
                await asgi_response(scope, receive, send)
                return

            except SuperTokensError as e:
                # SuperTokens error path
                err_resp_obj = Response(content=None)
                err_resp = LitestarResponse(err_resp_obj)

                handled = cast(
                    LitestarResponse,
                    await st.handle_supertokens_error(
                        custom_request, e, err_resp, user_context
                    ),
                )

                # Clear the session from request.state to prevent the middleware
                # from re-applying session cookies after we've cleared them
                if hasattr(litestar_request.state, "supertokens"):  # type: ignore
                    delattr(litestar_request.state, "supertokens")  # type: ignore

                asgi_response = handled.response.to_asgi_response(  # type: ignore
                    app=None, request=Request(scope, receive, send)
                )
                await asgi_response(scope, receive, send)
                return

            # Fallback
            fallback = Response(content=None, status_code=500)
            await fallback.to_asgi_response(
                app=None, request=Request(scope, receive, send)
            )(scope, receive, send)  # type: ignore

        # Mount the SuperTokens ASGI app to handle auth routes
        app_mount = asgi(self.mount_path, is_mount=True)(supertokens_asgi_app)
        app_config.route_handlers.append(app_mount)

        return app_config


def get_supertokens_plugin(mount_path: str = "/auth") -> SupertokensPlugin:
    """
    Get a configured SuperTokens plugin for Litestar.

    Args:
            mount_path: The path where the SuperTokens ASGI app will be mounted.
                       This is the external path that will be accessible (e.g., "/auth" or "/api/v1/auth").
                       The mounted app will receive requests relative to this path.

    Returns:
            A configured SupertokensPlugin instance

    Example:
            # Mount at /auth
            app = Litestar(
                    plugins=[get_supertokens_plugin(mount_path="/auth")]
            )

            # Mount at /api/v1/auth (when using Litestar app.path)
            app = Litestar(
                    path="api/v1",
                    plugins=[get_supertokens_plugin(mount_path="/auth")]
            )
            # This makes the auth routes available at /api/v1/auth externally
    """
    return SupertokensPlugin(mount_path=mount_path)
