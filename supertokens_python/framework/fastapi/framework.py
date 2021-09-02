from supertokens_python.framework.fastapi.fastapi_request import FastApiRequest
from supertokens_python.framework.fastapi.fastapi_response import FastApiResponse

from supertokens_python.framework.types import Framework


class FastapiFramework(Framework):
    def wrap_request(self, unwrapped):
        return FastApiRequest(unwrapped)

    def wrap_response(self, unwrapped):
        return FastApiResponse(unwrapped)
