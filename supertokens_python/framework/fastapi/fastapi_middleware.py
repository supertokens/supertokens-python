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

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


class Middleware(BaseHTTPMiddleware):

    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request, call_next: RequestResponseEndpoint):
        from supertokens_python.framework.fastapi.fastapi_request import FastApiRequest
        from supertokens_python.framework.fastapi.fastapi_response import FastApiResponse
        from supertokens_python import Supertokens
        from supertokens_python.exceptions import SuperTokensError
        from supertokens_python.recipe.session import Session
        from supertokens_python.supertokens import manage_cookies_post_response
        st = Supertokens.get_instance()
        from fastapi.responses import Response

        try:
            custom_request = FastApiRequest(request)
            response = FastApiResponse(Response())
            result = await st.middleware(custom_request, response)
            if result is None:
                response = await call_next(request)
                result = FastApiResponse(response)

            if hasattr(request.state, "supertokens") and isinstance(
                    request.state.supertokens, Session):
                manage_cookies_post_response(request.state.supertokens, result)
            return result.response
        except SuperTokensError as e:
            response = FastApiResponse(Response())
            result = await st.handle_supertokens_error(FastApiRequest(request), e, response)
            return result.response
