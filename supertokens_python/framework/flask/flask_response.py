from werkzeug.http import dump_cookie

from supertokens_python.framework.response import BaseResponse


class FlaskResponse(BaseResponse):

    def __init__(self, response=None):
        super().__init__({})
        self.response = response
        self.headers = list()

    def set_cookie(self, key: str, value: str = "", max_age: int = None, expires: int = None, path: str = "/",
                   domain: str = None, secure: bool = False, httponly: bool = False, samesite: str = "lax"):
        if self.response is None:
            self.headers.append(("Set-Cookie",
                                 dump_cookie(
                                     key,
                                     value=value,
                                     max_age=max_age,
                                     expires=expires,
                                     path=path,
                                     domain=domain,
                                     secure=secure,
                                     httponly=httponly,
                                     samesite=samesite
                                 )))
        else:
            self.response.set_cookie(key, value)

    def set_header(self, key, value):
        if self.response is None:
            # TODO in the future the headrs must be validated..
            if not isinstance(value, str):
                raise TypeError("Value should be unicode.")
            if u"\n" in value or u"\r" in value:
                raise ValueError(
                    "Detected newline in header value.  This is "
                    "a potential security problem"
                )
            self.headers.append((key, value))
        else:
            self.response.headers.add(key, value)

    def get_header(self, key):
        if self.response is not None:
            return self.response.headers.get(key)
        else:
            for value in self.headers:
                if value[0] == key:
                    return value[1]
            return None

    def set_status_code(self, status_code):
        self.response.status = status_code

    def get_headers(self):
        if self.response is None:
            return self.headers
        else:
            return self.response.headers
