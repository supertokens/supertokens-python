from functools import wraps

from asgiref.sync import async_to_sync
from flask import Request, request, make_response, g


def supertokens_middleware(anti_csrf_check=None):
    def session_verify(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):

            from supertokens_python.framework.flask.flask_request import FlaskRequest
            from supertokens_python.framework.flask.flask_response import FlaskResponse
            from supertokens_python import Supertokens
            from supertokens_python.supertokens import manage_cookies_post_response
            from flask import Response

            st = Supertokens.get_instance()
            flask_request = FlaskRequest(request)
            response = FlaskResponse(Response())
            result = async_to_sync(st.middleware)(flask_request, response)

            if result is None:
                response = make_response(f(*args, **kwargs))

            if hasattr(g, 'supertokens'):
                manage_cookies_post_response(g.supertokens, response)

            return response

        return wrapped_function

    if callable(anti_csrf_check):
        func = anti_csrf_check
        anti_csrf_check = None
        return session_verify(func)
    return session_verify
