from abc import ABC, abstractmethod
from typing import (
    List,
)

from supertokens_python.querier import Querier

from .config import NormalizedPluginTestConfig
from .types import RecipeReturnType


class RecipeInterface(ABC):
    @abstractmethod
    def sign_in(self, message: str, stack: List[str]) -> RecipeReturnType: ...


class RecipeImplementation(RecipeInterface):
    def __init__(
        self,
        querier: Querier,
        config: NormalizedPluginTestConfig,
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
