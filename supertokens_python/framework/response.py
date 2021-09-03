from abc import ABC, abstractmethod


class BaseResponse(ABC):

    @abstractmethod
    def __init__(self, content: dict, status_code : int = 200):
        self.content = content
        self.status_code = status_code
        self.wrapper_used = True


    @abstractmethod
    def set_cookie(self, key: str,
                   value: str = "",
                   max_age: int = None,
                   expires: int = None,
                   path: str = "/",
                   domain: str = None,
                   secure: bool = False,
                   httponly: bool = False,
                   samesite: str = "Lax", ):
        pass

    @abstractmethod
    def set_header(self, key, value):
        pass

    @abstractmethod
    def get_header(self, key):
        pass


    @abstractmethod
    def set_status_code(self, status_code):
        pass

    @abstractmethod
    def set_content(self, content):
        pass