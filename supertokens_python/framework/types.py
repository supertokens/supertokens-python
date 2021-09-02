from abc import ABC, abstractmethod
from enum import Enum
from typing import Union

from supertokens_python.framework.request import BaseRequest
from supertokens_python.framework.response import BaseResponse

frameworks = ["Fastapi", "Flask", "Django"]


class FrameworkEnum(Enum):
    FASTAPI = 1,
    FLASK = 2,
    DJANGO = 3


class Framework(ABC):

    @abstractmethod
    def wrap_request(self, unwrapped) -> Union[BaseRequest, None]:
        pass

    @abstractmethod
    def wrap_response(self, unwrapped) -> Union[BaseResponse, None]:
        pass
