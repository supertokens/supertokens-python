from typing import List, Literal

from supertokens_python.types.response import CamelCaseBaseModel


class RecipeReturnType(CamelCaseBaseModel):
    type: Literal["Recipe", "API"]
    function: str
    stack: List[str]
    message: str
