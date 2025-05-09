from typing import Any, Dict, List

from typing_extensions import TypeAlias

from supertokens_python.types.response import CamelCaseBaseModel

# TODO: Should `UserContext` be optional to handle `None` and init with `{}`?
# TODO: Make this generic and re-use across codebase?
UserContext: TypeAlias = Dict[str, Any]


class WebauthnInfo(CamelCaseBaseModel):
    credential_ids: List[str]


class WebauthnInfoInput(CamelCaseBaseModel):
    credential_id: str
