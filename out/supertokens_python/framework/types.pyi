import abc
from abc import ABC, abstractmethod
from enum import Enum
from supertokens_python.framework.request import BaseRequest as BaseRequest
from typing import Any, Union

frameworks: Any

class FrameworkEnum(Enum):
    FASTAPI: int
    FLASK: int
    DJANGO: int

class Framework(ABC, metaclass=abc.ABCMeta):
    @abstractmethod
    def wrap_request(self, unwrapped: Any) -> Union[BaseRequest, None]: ...
