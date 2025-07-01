from typing import Any, TypeVar

from pydantic import BeforeValidator
from pydantic_core import PydanticUseDefault
from typing_extensions import Annotated

T = TypeVar("T")


def default_if_none(value: Any) -> Any:
    if value is None:
        return PydanticUseDefault()
    return value


UseDefaultIfNone = Annotated[T, BeforeValidator(default_if_none)]
