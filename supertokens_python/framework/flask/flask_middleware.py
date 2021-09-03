import json

from asgiref.sync import async_to_sync
from werkzeug.wrappers import Request, Response

from supertokens_python.framework.flask.flask_request import FlaskRequest
from supertokens_python.framework.flask.flask_response import FlaskResponse
from supertokens_python import Supertokens
from supertokens_python.exceptions import SuperTokensError
from supertokens_python.supertokens import manage_cookies_post_response


class Middleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        st = Supertokens.get_instance()
        request = FlaskRequest(environ)
        # try:
        result = async_to_sync(st.middleware)(request)

        if result is None:
            self.app(environ, start_response)

        response = FlaskResponse()

        if 'additional_storage' in environ:
            manage_cookies_post_response(environ['additional_storage'], response)

        def injecting_start_response(status, headers, exc_info=None):
            headers = response.get_headers()
            return start_response(status, headers, exc_info)
        return self.app(environ, injecting_start_response)
        # except SuperTokensError as e:
        #     response = FlaskResponse(Response(environ))
        #     result = async_to_sync(st.handle_supertokens_error)(request, e, response)
        #     def injecting_start_response(status, headers, exc_info=None):
        #         headers = response.get_headers()
        #         return start_response(status, headers, exc_info)
        #     return self.app(environ, injecting_start_response)
