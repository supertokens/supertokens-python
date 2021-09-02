from typing import Union
from supertokens_python.framework.request import BaseRequest


class FastApiRequest(BaseRequest):

    def __init__(self, request):
        super().__init__()
        self.request = request
        self.original = request

    def get_query_param(self, key, default = None):
        return self.request.query_params.get(key, default)

    async def json(self):
        return await self.request.json()

    def method(self) -> str:
        return self.request.method

    def get_cookie(self, key: str) -> Union[str, None]:
        return self.request.cookies.get(key)

    def get_header(self, key: str) -> Union[str, None]:
        return self.request.headers.get(key)

    @property
    def url(self):
        return self.request.url

    def get_session(self):
        return self.request.state.supertokens

    def set_session(self, session):
        self.request.state.supertokens = session

    def get_path(self) -> str:
        return self.request.url.path
