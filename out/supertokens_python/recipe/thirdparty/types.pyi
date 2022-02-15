from supertokens_python.framework.request import BaseRequest as BaseRequest
from typing import Any, Callable, Dict, List, Union

class ThirdPartyInfo:
    user_id: Any
    id: Any
    def __init__(self, third_party_user_id: str, third_party_id: str) -> None: ...

class User:
    user_id: Any
    email: Any
    time_joined: Any
    third_party_info: Any
    def __init__(self, user_id: str, email: str, time_joined: int, third_party_info: ThirdPartyInfo) -> None: ...

class UserInfoEmail:
    id: Any
    is_verified: Any
    def __init__(self, email: str, email_verified: bool) -> None: ...

class UserInfo:
    user_id: Any
    email: Any
    def __init__(self, user_id: str, email: Union[UserInfoEmail, None] = ...) -> None: ...

class AccessTokenAPI:
    url: Any
    params: Any
    def __init__(self, url: str, params: Dict[str, str]) -> None: ...

class AuthorisationRedirectAPI:
    url: Any
    params: Any
    def __init__(self, url: str, params: Dict[str, Union[Callable[[BaseRequest], str], str]]) -> None: ...

class SignInUpResponse:
    user: Any
    is_new_user: Any
    def __init__(self, user: User, is_new_user: bool) -> None: ...

class UsersResponse:
    users: Any
    next_pagination_token: Any
    def __init__(self, users: List[User], next_pagination_token: Union[str, None]) -> None: ...
