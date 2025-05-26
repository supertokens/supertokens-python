from typing import List

from supertokens_python.types.response import CamelCaseBaseModel


class WebauthnInfo(CamelCaseBaseModel):
    credential_ids: List[str]


class WebauthnInfoInput(CamelCaseBaseModel):
    credential_id: str
