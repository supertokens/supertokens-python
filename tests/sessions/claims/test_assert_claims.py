from typing import Any, Dict, TypeVar, Union
from unittest.mock import patch

from pytest import mark
from supertokens_python.recipe.session.claims import PrimitiveClaim
from supertokens_python.recipe.session.interfaces import (
    JSONObject,
    SessionClaimValidator,
    ClaimValidationResult,
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
        def __init__(self):
            super().__init__("claim_validator_id")
            self.validate_call_count = 0

        async def validate(
            self, payload: JSONObject, user_context: Union[Dict[str, Any], None] = None
        ):
            self.validate_call_count += 1
            return ClaimValidationResult(is_valid=True)

    dummy_claim = PrimitiveClaim("st-claim", lambda _, __: "Hello world")

    dummy_claim_validator = DummyClaimValidator()
    dummy_claim_validator.claim = dummy_claim

    dummy_claim.validators.dummy_claim_validator = dummy_claim_validator  # type: ignore

    with patch.object(
        Session,
        "update_access_token_payload",
        wraps=session.update_access_token_payload,
    ) as mock:
        await session.assert_claims([dummy_claim.validators.dummy_claim_validator])  # type: ignore
        mock.assert_not_called()

        assert dummy_claim_validator.validate_call_count == 1
