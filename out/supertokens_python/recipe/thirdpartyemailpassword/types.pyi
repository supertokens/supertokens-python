from ..thirdparty.types import ThirdPartyInfo as ThirdPartyInfo
from typing import Any, Union

class User:
    user_id: Any
    email: Any
    time_joined: Any
    third_party_info: Any
    def __init__(self, user_id: str, email: str, time_joined: int, third_party_info: Union[ThirdPartyInfo, None] = ...) -> None: ...
