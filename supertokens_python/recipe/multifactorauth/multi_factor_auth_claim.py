from typing import Any, Dict, List, Optional, Union

from supertokens_python.recipe.session.interfaces import (
    ClaimValidationResult,
    JSONObject,
    SessionClaim,
    SessionClaimValidator,
)
from supertokens_python.types import RecipeUserId

from .types import MFAClaimValue, MFARequirementList
from .utils import update_and_get_mfa_related_info_in_session

# class IncludesSCV(SessionClaimValidator):
#     async def validate(
#         self,
#         payload: JSONObject,
#         user_context: Dict[str, Any],
#     ):
#         return await self._validate(payload, user_context, is_include=True)


class MultiFactorAuthClaimClass(SessionClaim[MFAClaimValue]):
    def __init__(self, key: Optional[str] = None):
        super().__init__(key or "st-mfa")
        self.validators = {
            "has_completed_mfa_requirements_for_auth": self._has_completed_mfa_requirements_for_auth,
            "has_completed_requirement_list": self._has_completed_requirement_list,
        }

    def _has_completed_mfa_requirements_for_auth(
        self, claim_key: Optional[str] = None
    ) -> SessionClaimValidator:

        return {
            "claim": self,
            "id": claim_key or self.key,
            "should_refetch": lambda payload: self.get_value_from_payload(payload)
            is None,
            "validate": self._validate_mfa_requirements_for_auth,
        }

    async def _validate_mfa_requirements_for_auth(
        self, payload: JSONObject
    ) -> ClaimValidationResult:
        claim_val = self.get_value_from_payload(payload)
        if claim_val is None:
            raise Exception(
                "This should never happen, claim value not present in payload"
            )

        v = claim_val["v"]
        return ClaimValidationResult(
            is_valid=v,
            reason=None
            if v
            else {"message": "MFA requirement for auth is not satisfied"},
        )

    def _has_completed_requirement_list(
        self, requirement_list: MFARequirementList, claim_key: Optional[str] = None
    ) -> SessionClaimValidator:
        return {
            "claim": self,
            "id": claim_key or self.key,
            "should_refetch": lambda payload: self.get_value_from_payload(payload)
            is None,
            "validate": lambda payload: self._validate_requirement_list(
                payload, requirement_list
            ),
        }

    async def _validate_requirement_list(
        self, payload: JSONObject, requirement_list: MFARequirementList
    ) -> ClaimValidationResult:
        if not requirement_list:
            return ClaimValidationResult(is_valid=True)

        claim_val = self.get_value_from_payload(payload)
        if claim_val is None:
            raise Exception(
                "This should never happen, claim value not present in payload"
            )

        completed_factors = claim_val["c"]
        next_unsatisfied_factors = self.get_next_set_of_unsatisfied_factors(
            completed_factors, requirement_list
        )

        if not next_unsatisfied_factors["factor_ids"]:
            return ClaimValidationResult(is_valid=True)

        factor_type = next_unsatisfied_factors["type"]
        factor_ids = next_unsatisfied_factors["factor_ids"]

        if factor_type == "string":
            return ClaimValidationResult(
                is_valid=False,
                reason={
                    "message": f"Factor validation failed: {factor_ids[0]} not completed",
                    "factor_id": factor_ids[0],
                },
            )
        elif factor_type == "oneOf":
            return ClaimValidationResult(
                is_valid=False,
                reason={
                    "message": f"None of these factors are complete in the session: {', '.join(factor_ids)}",
                    "one_of": factor_ids,
                },
            )
        else:
            return ClaimValidationResult(
                is_valid=False,
                reason={
                    "message": f"Some of the factors are not complete in the session: {', '.join(factor_ids)}",
                    "all_of_in_any_order": factor_ids,
                },
            )

    def get_next_set_of_unsatisfied_factors(
        self, completed_factors: Dict[str, Any], requirement_list: MFARequirementList
    ) -> Dict[str, Union[List[str], str]]:
        for req in requirement_list:
            next_factors = set()
            factor_type = "string"

            if isinstance(req, str):
                if req not in completed_factors:
                    factor_type = "string"
                    next_factors.add(req)
            elif isinstance(req, dict):
                if "oneOf" in req:
                    satisfied = any(
                        factor_id in completed_factors for factor_id in req["oneOf"]
                    )
                    if not satisfied:
                        factor_type = "oneOf"
                        next_factors.update(req["oneOf"])
                elif "allOfInAnyOrder" in req:
                    factor_type = "allOfInAnyOrder"
                    next_factors.update(
                        factor_id
                        for factor_id in req["allOfInAnyOrder"]
                        if factor_id not in completed_factors
                    )

            if next_factors:
                return {
                    "factor_ids": list(next_factors),
                    "type": factor_type,
                }

        return {
            "factor_ids": [],
            "type": "string",
        }

    async def fetch_value(
        self,
        user_id: str,
        recipe_user_id: RecipeUserId,
        tenant_id: str,
        current_payload: Optional[JSONObject],
        user_context: Dict[str, Any],
    ) -> MFAClaimValue:
        mfa_info = await update_and_get_mfa_related_info_in_session(
            session_recipe_user_id=recipe_user_id,
            tenant_id=tenant_id,
            access_token_payload=current_payload,
            user_context=user_context,
        )
        completed_factors, is_mfa_requirements_for_auth_satisfied = (
            mfa_info["completed_factors"],
            mfa_info["is_mfa_requirements_for_auth_satisfied"],
        )
        return {
            "c": completed_factors,
            "v": is_mfa_requirements_for_auth_satisfied,
        }

    def add_to_payload_internal(
        self, payload: JSONObject, value: MFAClaimValue
    ) -> JSONObject:
        prev_value = payload.get(self.key, {})
        return {
            **payload,
            self.key: {
                "c": {**prev_value.get("c", {}), **value["c"]},
                "v": value["v"],
            },
        }

    def remove_from_payload(self, payload: JSONObject) -> JSONObject:
        return {key: value for key, value in payload.items() if key != self.key}

    def remove_from_payload_by_merge_internal(self) -> JSONObject:
        return {self.key: None}

    def get_value_from_payload(self, payload: JSONObject) -> Optional[MFAClaimValue]:
        return payload.get(self.key)


MultiFactorAuthClaim = MultiFactorAuthClaimClass()
