from fastapi import Request as Request
from supertokens_python.framework.fastapi.fastapi_request import FastApiRequest as FastApiRequest
from supertokens_python.framework.types import Framework as Framework

class FastapiFramework(Framework):
    def wrap_request(self, unwrapped: Request): ...
