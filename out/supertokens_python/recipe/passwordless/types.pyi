from typing import Any, List, Union

class User:
    user_id: Any
    email: Any
    phone_number: Any
    time_joined: Any
    def __init__(self, user_id: str, email: Union[str, None], phone_number: Union[str, None], time_joined: int) -> None: ...

class DeviceCode:
    code_id: Any
    time_created: Any
    code_life_time: Any
    def __init__(self, code_id: str, time_created: str, code_life_time: int) -> None: ...

class DeviceType:
    pre_auth_session_id: Any
    failed_code_input_attempt_count: Any
    codes: Any
    email: Any
    phone_number: Any
    def __init__(self, pre_auth_session_id: str, failed_code_input_attempt_count: int, codes: List[DeviceCode], email: Union[str, None] = ..., phone_number: Union[str, None] = ...) -> None: ...
