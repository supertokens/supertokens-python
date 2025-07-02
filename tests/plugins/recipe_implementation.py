from abc import abstractmethod
from typing import (
    TYPE_CHECKING,
    List,
)

from supertokens_python.querier import Querier
from supertokens_python.types.recipe import BaseRecipeInterface

from .types import RecipeReturnType

if TYPE_CHECKING:
    from .config import NormalizedPluginTestConfig


class RecipeInterface(BaseRecipeInterface):
    @abstractmethod
    def sign_in(self, message: str, stack: List[str]) -> RecipeReturnType: ...


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        querier: Querier,
        config: "NormalizedPluginTestConfig",
    ):
        super().__init__()
        self.querier = querier
        self.config = config

    def sign_in(self, message: str, stack: List[str]) -> RecipeReturnType:
        stack.append("original")
        return RecipeReturnType(
            type="Recipe",
            function="sign_in",
            stack=stack,
            message=message,
        )
