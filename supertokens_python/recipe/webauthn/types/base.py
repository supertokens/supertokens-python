from __future__ import annotations

from typing import Any, Dict

from typing_extensions import TypeAlias

from supertokens_python.types.response import CamelCaseBaseModel

# TODO: Should `UserContext` be optional to handle `None` and init with `{}`?
# TODO: Make this generic and re-use across codebase?
UserContext: TypeAlias = Dict[str, Any]


class WebauthnInfo(CamelCaseBaseModel):
    credential_id: str
