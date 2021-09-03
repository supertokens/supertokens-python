from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from supertokens_python.framework.fastapi.fastapi_request import FastApiRequest
from supertokens_python.framework.fastapi.fastapi_response import FastApiResponse
from supertokens_python import Supertokens
from supertokens_python.exceptions import SuperTokensError
from supertokens_python.session import Session
from supertokens_python.supertokens import manage_cookies_post_response
from starlette.responses import JSONResponse

class Middleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request, call_next: RequestResponseEndpoint):
        st = Supertokens.get_instance()

        try:
            custom_request = FastApiRequest(request)
            result = await st.middleware(custom_request)
            if result is None:
                response = await call_next(request)
                result = FastApiResponse(response)

            if hasattr(request.state, "supertokens") and isinstance(request.state.supertokens, Session):
                manage_cookies_post_response(request.state.supertokens, result)
            print(request.state)
            return result.response
        except SuperTokensError as e:
            response = FastApiResponse(JSONResponse())
            result = await st.handle_supertokens_error(FastApiRequest(request), e, response)
            return result.response









