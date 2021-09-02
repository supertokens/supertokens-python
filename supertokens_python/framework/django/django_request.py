import json
from typing import Any, Union
from supertokens_python.framework.request import BaseRequest


class DjangoRequest(BaseRequest):

    def __init__(self, request):
        super().__init__()
        self.request = request

    def get_query_param(self, key, default=None):
        return self.request.GET.get(key, default)

    def json(self):
        body = json.loads(self.request.body)
        return body

    def method(self) -> str:
        return self.request.method

    def get_cookie(self, key: str) -> Union[str, None]:
        return self.request.COOKIES.get(key)

    def get_header(self, key: str) -> Any:
        return self.request.headers.get(key)

    def url(self):
        return self.request.get_full_path()

    def get_session(self):
        return self.request.state

    def set_session(self, session):
        self.request.state = session

    def get_path(self) -> str:
        return self.request.path
