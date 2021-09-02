from abc import ABC, abstractmethod
from typing import Any, Union

class BaseRequest(ABC):
    
    def __init__(self):
        self.wrapper_used = True

    @abstractmethod
    def get_query_param(self, key, default = None):
        pass

    @abstractmethod
    def json(self):
        pass

    @abstractmethod
    def method(self) -> str:
        pass

    @abstractmethod
    def get_cookie(self, key: str) -> Union[str, None]:
        pass

    @abstractmethod
    def get_header(self, key: str) -> Any:
        pass

    @abstractmethod
    def url(self):
        pass

    @abstractmethod
    def get_session(self):
        pass

    @abstractmethod
    def set_session(self, session):
        pass

    @abstractmethod
    def get_path(self) -> str:
        pass


