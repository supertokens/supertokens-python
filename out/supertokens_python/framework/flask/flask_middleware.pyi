from flask import Flask as Flask
from supertokens_python.async_to_sync_wrapper import sync as sync
from supertokens_python.framework import BaseResponse as BaseResponse
from typing import Any

class Middleware:
    app: Any
    def __init__(self, app: Flask) -> None: ...
    def set_before_after_request(self): ...
    def set_error_handler(self): ...
