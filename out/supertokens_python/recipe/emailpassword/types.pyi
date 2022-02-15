from typing import Any, Awaitable, Callable, List, Union

class User:
    user_id: Any
    email: Any
    time_joined: Any
    third_party_info: Any
    def __init__(self, user_id: str, email: str, time_joined: int) -> None: ...

class UsersResponse:
    users: Any
    next_pagination_token: Any
    def __init__(self, users: List[User], next_pagination_token: Union[str, None]) -> None: ...

class ErrorFormField:
    id: Any
    error: Any
    def __init__(self, id: str, error: str) -> None: ...

class FormField:
    id: Any
    value: Any
    def __init__(self, id: str, value: str) -> None: ...

class InputFormField:
    id: Any
    validate: Any
    optional: Any
    def __init__(self, id: str, validate: Union[Callable[[str], Awaitable[Union[str, None]]], None] = ..., optional: Union[bool, None] = ...) -> None: ...

class NormalisedFormField:
    id: Any
    validate: Any
    optional: Any
    def __init__(self, id: str, validate: Callable[[str], Awaitable[Union[str, None]]], optional: bool) -> None: ...
