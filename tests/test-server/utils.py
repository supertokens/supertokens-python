from typing import Any, Dict

from override_logging import log_override_event  # pylint: disable=import-error
from supertokens_python.recipe.emailverification import EmailVerificationClaim
from supertokens_python.recipe.multifactorauth.multi_factor_auth_claim import (
    MultiFactorAuthClaim,
)
from supertokens_python.recipe.session.claims import (
    BooleanClaim,
    PrimitiveClaim,
    SessionClaim,
)
from supertokens_python.recipe.session.interfaces import SessionClaimValidator
from supertokens_python.recipe.userroles import PermissionClaim, UserRoleClaim
from supertokens_python.types import RecipeUserId, User


def mock_claim_builder(key: str, values: Any) -> PrimitiveClaim[Any]:
    def fetch_value(
        user_id: str,
        recipe_user_id: RecipeUserId,
        tenant_id: str,
        current_payload: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> Any:
        log_override_event(
            f"claim-{key}.fetchValue",
            "CALL",
            {
                "userId": user_id,
                "recipeUserId": recipe_user_id.get_as_string(),
                "tenantId": tenant_id,
                "currentPayload": current_payload,
                "userContext": user_context,
            },
        )

        ret_val: Any = user_context.get("st-stub-arr-value") or (
            values[0]
            if isinstance(values, list) and isinstance(values[0], list)
            else values
        )
        log_override_event(f"claim-{key}.fetchValue", "RES", ret_val)

        return ret_val

    return PrimitiveClaim(key=key or "st-stub-primitive", fetch_value=fetch_value)


test_claim_setups: Dict[str, SessionClaim[Any]] = {
    "st-true": BooleanClaim(
        key="st-true",
        fetch_value=lambda *_args, **_kwargs: True,  # type: ignore
    ),
    "st-undef": BooleanClaim(
        key="st-undef",
        fetch_value=lambda *_args, **_kwargs: None,  # type: ignore
    ),
}

# Add all built-in claims
for claim in [
    EmailVerificationClaim,
    MultiFactorAuthClaim,
    UserRoleClaim,
    PermissionClaim,
]:
    test_claim_setups[claim.key] = claim  # type: ignore


def deserialize_claim(serialized_claim: Dict[str, Any]) -> SessionClaim[Any]:
    key = serialized_claim["key"]

    if key.startswith("st-stub-"):
        return mock_claim_builder(key.replace("st-stub-", "", 1), serialized_claim)

    return test_claim_setups[key]


def deserialize_validator(validatorsInput: Any) -> SessionClaimValidator:  # type: ignore
    key = validatorsInput["key"]
    if key in test_claim_setups:
        claim = test_claim_setups[key]
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


def serialize_user(user: User, fdi_version: str) -> Dict[str, Any]:
    if get_max_version("1.17", fdi_version) == "1.17" or (
        get_max_version("2.0", fdi_version) == fdi_version
        and get_max_version("3.0", fdi_version) != fdi_version
    ):
        return {
            "user": {
                "id": user.id,
                "email": user.emails[0],
                "timeJoined": user.time_joined,
                "tenantIds": user.tenant_ids,
            }
        }
    else:
        return {"user": user.to_json()}


def serialize_recipe_user_id(
    recipe_user_id: RecipeUserId, fdi_version: str
) -> Dict[str, Any]:
    if get_max_version("1.17", fdi_version) == "1.17" or (
        get_max_version("2.0", fdi_version) == fdi_version
        and get_max_version("3.0", fdi_version) != fdi_version
    ):
        return {}
    else:
        return {"recipeUserId": recipe_user_id.get_as_string()}
