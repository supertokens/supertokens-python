from typing import Literal


class ValidFirstFactorResponse:
    def __init__(
        self,
        status: Literal["OK", "INVALID_FIRST_FACTOR_ERROR", "TENANT_NOT_FOUND_ERROR"],
    ) -> None:
        self.status = status
