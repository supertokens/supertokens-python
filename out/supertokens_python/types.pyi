from typing import Any, List, Union

class ThirdPartyInfo:
    user_id: Any
    id: Any
    def __init__(self, third_party_user_id: str, third_party_id: str) -> None: ...

class User:
    recipe_id: Any
    user_id: Any
    email: Any
    time_joined: Any
    third_party_info: Any
    phone_number: Any
    def __init__(self, recipe_id: str, user_id: str, time_joined: int, email: Union[str, None], phone_number: Union[str, None], third_party_info: Union[ThirdPartyInfo, None]) -> None: ...

class UsersResponse:
    users: Any
    next_pagination_token: Any
    def __init__(self, users: List[User], next_pagination_token: Union[str, None]) -> None: ...
