from abc import abstractmethod
from typing import (
    List,
)

from supertokens_python.types.recipe import BaseAPIInterface

from .types import RecipeReturnType


class APIInterface(BaseAPIInterface):
    @abstractmethod
    def sign_in_post(self, message: str, stack: List[str]) -> RecipeReturnType: ...


class APIImplementation(APIInterface):
    def sign_in_post(self, message: str, stack: List[str]) -> RecipeReturnType:
        stack.append("original")
        return RecipeReturnType(
            type="API",
            function="sign_in_post",
            stack=stack,
            message=message,
        )
