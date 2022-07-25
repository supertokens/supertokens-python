from typing import Union, Dict, Any, TypeVar, Optional
from unittest.mock import AsyncMock, patch

from pytest import mark

from supertokens_python.recipe.session.claims import PrimitiveClaim
from supertokens_python.recipe.session.interfaces import (
    SessionClaimValidator,
    JSONObject,
)
from supertokens_python.recipe.session.session_class import Session

_T = TypeVar("_T")


@mark.asyncio
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


@mark.asyncio
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
        id = "claim_validator_id"

        async def validate(
            self, payload: JSONObject, user_context: Union[Dict[str, Any], None] = None
        ):
            return {"isValid": True}

    class DummyClaim(PrimitiveClaim):
        def __init__(self):
            super().__init__("st-claim")

        def fetch_value(
            self, user_id: str, user_context: Optional[Dict[str, Any]] = None
        ):
            return "Hello world"

    dummy_claim = DummyClaim()

    dummy_claim_validator = DummyClaimValidator()
    dummy_claim_validator.claim = dummy_claim

    dummy_claim.validators.dummy_claim_validator = dummy_claim_validator  # type: ignore

    with patch.object(
        Session,
        "update_access_token_payload",
        wraps=session.update_access_token_payload,
    ) as mock:
        await session.assert_claims([dummy_claim.validators.dummy_claim_validator])  # type: ignore
        params, _ = mock.call_args.args
        assert params["st-claim"]["t"] > 0
        params["st-claim"]["t"] = 0
        assert params == {**payload, "st-claim": {"v": "Hello world", "t": 0}}
