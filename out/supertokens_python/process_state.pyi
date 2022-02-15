from enum import Enum
from typing import Any

class AllowedProcessStates(Enum):
    CALLING_SERVICE_IN_VERIFY: int
    CALLING_SERVICE_IN_GET_HANDSHAKE_INFO: int
    CALLING_SERVICE_IN_GET_API_VERSION: int
    CALLING_SERVICE_IN_REQUEST_HELPER: int

class ProcessState:
    history: Any
    def __init__(self) -> None: ...
    @staticmethod
    def get_instance(): ...
    def add_state(self, state: AllowedProcessStates): ...
    def reset(self) -> None: ...
