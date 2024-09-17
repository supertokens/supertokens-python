from __future__ import annotations

from typing import Any, Dict, Optional, Set

from supertokens_python.recipe.session.interfaces import (
    ClaimValidationResult,
    JSONObject,
    SessionClaim,
    SessionClaimValidator,
)
from supertokens_python.types import RecipeUserId

from .types import (
    FactorIdsAndType,
    MFAClaimValue,
    MFARequirementList,
)
from .utils import update_and_get_mfa_related_info_in_session


class HasCompletedRequirementListSCV(SessionClaimValidator):
    def __init__(
        self,
        id_: str,
        claim: MultiFactorAuthClaimClass,
        requirement_list: MFARequirementList,
    ):
        super().__init__(id_)
        self.claim: MultiFactorAuthClaimClass = claim
        self.requirement_list = requirement_list

    async def should_refetch(
        self, payload: Dict[str, Any], user_context: Dict[str, Any]
    ) -> bool:
        return (
            True
            if self.claim.key not in payload or not payload[self.claim.key]
            else False
        )

    async def validate(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> ClaimValidationResult:
        if len(self.requirement_list) == 0:
            return ClaimValidationResult(is_valid=True)  # no requirements to satisfy

        if (self.claim.key not in payload) or (not payload[self.claim.key]):
            raise Exception(
                "This should never happen, claim value not present in payload"
            )

        claim_val: MFAClaimValue = payload[self.claim.key]

        completed_factors = claim_val.c
        next_set_of_unsatisfied_factors = (
            self.claim.get_next_set_of_unsatisfied_factors(
                completed_factors, self.requirement_list
            )
        )

        if len(next_set_of_unsatisfied_factors.factor_ids) == 0:
            return ClaimValidationResult(
                is_valid=True
            )  # No item in the requirementList is left unsatisfied, hence is Valid

        factor_ids = next_set_of_unsatisfied_factors.factor_ids

        if next_set_of_unsatisfied_factors.type == "string":
            return ClaimValidationResult(
                is_valid=False,
                reason={
                    "message": f"Factor validation failed: {factor_ids[0]} not completed",
                    "factor_id": factor_ids[0],
                },
            )

        elif next_set_of_unsatisfied_factors.type == "oneOf":
            return ClaimValidationResult(
                is_valid=False,
                reason={
                    "reason": f"None of these factors are complete in the session: {', '.join(factor_ids)}",
                    "one_of": factor_ids,
                },
            )
        else:
            return ClaimValidationResult(
                is_valid=False,
                reason={
                    "reason": f"Some of the factors are not complete in the session: {', '.join(factor_ids)}",
                    "all_of_in_any_order": factor_ids,
                },
            )


class HasCompletedMFARequirementsForAuthSCV(SessionClaimValidator):
    def __init__(
        self,
        id_: str,
        claim: MultiFactorAuthClaimClass,
    ):
        super().__init__(id_)
        self.claim = claim

    async def should_refetch(
        self, payload: Dict[str, Any], user_context: Dict[str, Any]
    ) -> bool:
        assert self.claim is not None
        return (
            True
            if self.claim.key not in payload or not payload[self.claim.key]
            else False
        )

    async def validate(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> ClaimValidationResult:
        assert self.claim is not None
        if self.claim.key not in payload or not payload[self.claim.key]:
            raise Exception(
                "This should never happen, claim value not present in payload"
            )
        claim_val: MFAClaimValue = payload[self.claim.key]

        return ClaimValidationResult(
            is_valid=claim_val.v,
            reason=(
                {
                    "message": "MFA requirement for auth is not satisfied",
                }
                if not claim_val.v
                else None
            ),
        )


class MultiFactorAuthClaimValidators:
    def __init__(self, claim: MultiFactorAuthClaimClass):
        self.claim = claim

    def has_completed_requirement_list(
        self, requirement_list: MFARequirementList, claim_key: Optional[str] = None
    ) -> SessionClaimValidator:
        return HasCompletedRequirementListSCV(
            id_=claim_key or self.claim.key,
            claim=self.claim,
            requirement_list=requirement_list,
        )

    def has_completed_mfa_requirements_for_auth(
        self, claim_key: Optional[str] = None
    ) -> SessionClaimValidator:

        return HasCompletedMFARequirementsForAuthSCV(
            id_=claim_key or self.claim.key,
            claim=self.claim,
        )


class MultiFactorAuthClaimClass(SessionClaim[MFAClaimValue]):
    def __init__(self, key: Optional[str] = None):
        key = key or "st-mfa"

        async def fetch_value(
            user_id: str,
            recipe_user_id: RecipeUserId,
            tenant_id: str,
            current_payload: Dict[str, Any],
            user_context: Dict[str, Any],
        ) -> MFAClaimValue:
            mfa_info = await update_and_get_mfa_related_info_in_session(
                input_session_recipe_user_id=recipe_user_id,
                input_tenant_id=tenant_id,
                input_access_token_payload=current_payload,
                user_context=user_context,
            )
            return MFAClaimValue(
                c=mfa_info.completed_factors,
                v=mfa_info.is_mfa_requirements_for_auth_satisfied,
            )

        super().__init__(key or "st-mfa", fetch_value=fetch_value)
        self.validators = MultiFactorAuthClaimValidators(claim=self)

    def get_next_set_of_unsatisfied_factors(
        self, completed_factors: Dict[str, int], requirement_list: MFARequirementList
    ) -> FactorIdsAndType:
        for req in requirement_list:
            next_factors: Set[str] = set()
            factor_type = "string"

            if isinstance(req, str):
                if req not in completed_factors:
                    factor_type = "string"
                    next_factors.add(req)
            else:
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

            if len(next_factors) > 0:
                return FactorIdsAndType(factor_ids=list(next_factors), type=factor_type)

        return FactorIdsAndType(factor_ids=[], type="string")

    def add_to_payload_(
        self,
        payload: JSONObject,
        value: MFAClaimValue,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> JSONObject:
        prev_value = payload.get(self.key, {})
        return {
            **payload,
            self.key: {
                "c": {**prev_value.get("c", {}), **value.c},
                "v": value.v,
            },
        }

    def remove_from_payload(
        self, payload: JSONObject, user_context: Optional[Dict[str, Any]] = None
    ) -> JSONObject:
        del payload[self.key]
        return payload

    def remove_from_payload_by_merge_(
        self, payload: JSONObject, user_context: Optional[Dict[str, Any]] = None
    ) -> JSONObject:
        payload[self.key] = None
        return payload

    def get_value_from_payload(
        self, payload: JSONObject, user_context: Optional[Dict[str, Any]] = None
    ) -> Optional[MFAClaimValue]:
        return payload.get(self.key)


MultiFactorAuthClaim = MultiFactorAuthClaimClass()