from typing import Any, Dict

import pytest
from supertokens_python.recipe.session.access_token import (
    validate_access_token_structure,
)


def get_payload(version: int, **overrides: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "sub": "userid",
        "exp": 1000,
        "iat": 1000,
        "sessionHandle": "sessionhandle",
        "refreshTokenHash1": "hash",
    }
    if version >= 4:
        payload["tId"] = "public"
    if version >= 5:
        payload["rsub"] = "userid"
    payload.update(overrides)
    return payload


@pytest.mark.parametrize("version", [4, 5])
@pytest.mark.parametrize("tenant_id", [None, 1, {"id": "public"}, ["public"]])
def test_v4_and_later_tokens_require_a_string_tenant_id(version: int, tenant_id: Any):
    payload = get_payload(version, tId=tenant_id)

    with pytest.raises(Exception) as e:
        validate_access_token_structure(payload, version)

    assert (
        str(e.value)
        == "Access token does not contain all the information. Maybe the structure has changed?"
    )


@pytest.mark.parametrize("version", [4, 5])
def test_v4_and_later_tokens_require_a_tenant_id(version: int):
    payload = get_payload(version)
    del payload["tId"]

    with pytest.raises(Exception):
        validate_access_token_structure(payload, version)


@pytest.mark.parametrize("version", [4, 5])
def test_v4_and_later_tokens_with_a_string_tenant_id_are_valid(version: int):
    validate_access_token_structure(get_payload(version), version)


def test_v5_tokens_require_a_string_recipe_user_id():
    payload = get_payload(5)
    del payload["rsub"]

    with pytest.raises(Exception):
        validate_access_token_structure(payload, 5)


def test_v3_tokens_do_not_need_a_tenant_id():
    validate_access_token_structure(get_payload(3), 3)
    validate_access_token_structure(get_payload(3, tId=1), 3)


def test_v3_tokens_still_require_the_base_claims():
    payload = get_payload(3)
    del payload["sessionHandle"]

    with pytest.raises(Exception):
        validate_access_token_structure(payload, 3)


@pytest.mark.parametrize("version", [2, 3, 4, 5])
@pytest.mark.parametrize("stt", [1, 2, "0", None, False])
def test_tokens_with_a_non_session_token_type_are_rejected(version: int, stt: Any):
    if version == 2:
        payload: Dict[str, Any] = {
            "sessionHandle": "sessionhandle",
            "userId": "userid",
            "refreshTokenHash1": "hash",
            "userData": {},
            "expiryTime": 1000,
            "timeCreated": 1000,
            "stt": stt,
        }
    else:
        payload = get_payload(version, stt=stt)

    with pytest.raises(Exception) as e:
        validate_access_token_structure(payload, version)

    assert str(e.value) == "Wrong token type"


@pytest.mark.parametrize("version", [3, 4, 5])
def test_tokens_with_the_session_token_type_are_valid(version: int):
    validate_access_token_structure(get_payload(version, stt=0), version)


@pytest.mark.parametrize("version", [3, 4, 5])
def test_tokens_without_a_token_type_are_valid(version: int):
    payload = get_payload(version)
    assert "stt" not in payload
    validate_access_token_structure(payload, version)
