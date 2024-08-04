from typing import Any, Dict, List, Literal, Optional


class TenantConfig:
    def __init__(
        self,
        third_party: Dict[str, List[Dict[str, str]]],
        core_config: Dict[str, Any],
        first_factors: Optional[List[str]] = None,
        required_secondary_factors: Optional[List[str]] = None,
    ):
        self.third_party = third_party
        self.core_config = core_config
        self.first_factors = first_factors
        self.required_secondary_factors = required_secondary_factors


class ValidFirstFactorResponse:
    def __init__(
        self,
        status: Literal["OK", "INVALID_FIRST_FACTOR_ERROR", "TENANT_NOT_FOUND_ERROR"],
    ) -> None:
        self.status = status
