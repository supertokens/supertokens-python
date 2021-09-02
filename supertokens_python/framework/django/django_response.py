from supertokens_python.framework.response import BaseResponse


class DjangoResponse(BaseResponse):

    def __init__(self, response):
        super().__init__({})
        self.response = response
        self.original = response
        self.parser_checked = False

    def set_cookie(self, key: str, value: str = "", max_age: int = None, expires: int = None, path: str = "/",
                   domain: str = None, secure: bool = False, httponly: bool = False, samesite: str = "Lax"):
        self.response.set_cookie(key, value, max_age, expires, path, domain, secure, httponly, samesite)

    def set_status_code(self, status_code):
        self.response.status_code = status_code

    def set_header(self, key, value):
        self.response.headers[key] = value

    def get_header(self, key):
        return self.response.headers.get(key, None)
