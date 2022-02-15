from flask.wrappers import Request as Request
from supertokens_python.framework.flask.flask_request import FlaskRequest as FlaskRequest
from supertokens_python.framework.types import Framework as Framework

class FlaskFramework(Framework):
    def wrap_request(self, unwrapped: Request): ...
