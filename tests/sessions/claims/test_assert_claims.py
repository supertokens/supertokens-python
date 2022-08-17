import json
from typing import Any, Dict, TypeVar, Union
from unittest.mock import patch

from pytest import mark
from supertokens_python.recipe.session.claims import PrimitiveClaim
from supertokens_python.recipe.session.interfaces import (
    JSONObject,
    SessionClaimValidator,
    ClaimValidationResult,
    SessionClaim,
)
from supertokens_python.recipe.session.session_class import Session
from tests.utils import AsyncMock

_T = TypeVar("_T")

pytestmark = mark.asyncio


async def test_should_not_throw_for_empty_array():
    recipe_implementation_mock = AsyncMock()
    session = Session(
        recipe_implementation_mock,
        "test_access_token",
        "test_session_handle",
        "test_user_id",
        {},
    )
    with patch.object(
        Session,
        "update_access_token_payload",
        wraps=session.update_access_token_payload,
    ) as mock:
        await session.assert_claims([])
        mock.assert_not_called()


async def test_should_call_validate_with_the_same_payload_object():
    recipe_implementation_mock = AsyncMock()
    payload = {"custom-key": "custom-value"}
    session = Session(
        recipe_implementation_mock,
        "test_access_token",
        "test_session_handle",
        "test_user_id",
        payload,
    )

    class DummyClaimValidator(SessionClaimValidator):
        def __init__(self, claim: SessionClaim[Any]):
            super().__init__("claim_validator_id", claim)
            self.validate_calls: Dict[str, int] = {}

        async def validate(
            self, payload: JSONObject, user_context: Union[Dict[str, Any], None] = None
        ):
            payload_json = json.dumps(payload)
            self.validate_calls[payload_json] = (
                self.validate_calls.get(payload_json, 0) + 1
            )
            return ClaimValidationResult(is_valid=True)

        def should_refetch(self, payload: JSONObject, user_context: Dict[str, Any]):
            return False

    dummy_claim = PrimitiveClaim("st-claim", lambda _, __: "Hello world")

    dummy_claim_validator = DummyClaimValidator(dummy_claim)

    dummy_claim.validators.dummy_claim_validator = dummy_claim_validator  # type: ignore

    with patch.object(
        Session,
        "update_access_token_payload",
        wraps=session.update_access_token_payload,
    ) as mock:
        await session.assert_claims([dummy_claim.validators.dummy_claim_validator])  # type: ignore

        assert dummy_claim_validator.validate_calls == {json.dumps(payload): 1}
        mock.assert_not_called()
