from supertokens_python.framework.flask.flask_request import FlaskRequest
from supertokens_python.framework.flask.flask_response import FlaskResponse
from supertokens_python.framework.types import Framework


class FlaskFramework(Framework):
    def wrap_request(self, unwrapped):
        return FlaskRequest(unwrapped)

    def wrap_response(self, unwrapped):
        return FlaskResponse()