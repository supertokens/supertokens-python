from typing import Any, Dict
from supertokens_python.recipe.session.claims import SessionClaim

from supertokens_python.recipe.session.interfaces import SessionClaimValidator

test_claims: Dict[str, SessionClaim] = {}  # type: ignore


def init_test_claims():
    add_builtin_claims()


def add_builtin_claims():
    from supertokens_python.recipe.emailverification import EmailVerificationClaim

    test_claims[EmailVerificationClaim.key] = EmailVerificationClaim


def deserialize_validator(validatorsInput: Any) -> SessionClaimValidator:  # type: ignore
    key = validatorsInput["key"]
    if key in test_claims:
        claim = test_claims[key]  # type: ignore
        validator_name = validatorsInput["validatorName"]
        if hasattr(claim.validators, toSnakeCase(validator_name)):  # type: ignore
            validator_func = getattr(claim.validators, toSnakeCase(validator_name))  # type: ignore
            args = validatorsInput.get("args", [])
            return validator_func(*args)
        else:
            raise Exception(
                f"Validator with name {validator_name} not found for claim {key}"
            )


def toSnakeCase(camel_case: str) -> str:
    result = camel_case[0].lower()
    for char in camel_case[1:]:
        if char.isupper():
            result += "_" + char.lower()
        else:
            result += char
    return result


def get_max_version(v1: str, v2: str) -> str:
    v1_split = v1.split(".")
    v2_split = v2.split(".")
    max_loop = min(len(v1_split), len(v2_split))

    for i in range(max_loop):
        if int(v1_split[i]) > int(v2_split[i]):
            return v1
        if int(v2_split[i]) > int(v1_split[i]):
            return v2

    if len(v1_split) > len(v2_split):
        return v1

    return v2
