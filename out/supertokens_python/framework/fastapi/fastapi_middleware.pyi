from fastapi import FastAPI as FastAPI, Request as Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint as RequestResponseEndpoint
from supertokens_python.framework import BaseResponse as BaseResponse

class Middleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI) -> None: ...
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint): ...
