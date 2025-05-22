from __future__ import annotations

from typing import TYPE_CHECKING, Optional, cast

from pydantic import ValidationError

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework.response import BaseResponse
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    InvalidCredentialsErrorResponse,
    RegistrationPayload,
)
from supertokens_python.recipe.webauthn.types.base import UserContext
from supertokens_python.utils import (
    get_backwards_compatible_user_info,
    get_normalised_should_try_linking_with_session_user_flag,
    send_200_response,
)

if TYPE_CHECKING:
    from supertokens_python.recipe.webauthn.interfaces.api import (
        ApiInterface,
        APIOptions,
    )


async def sign_up_api(
    api_implementation: ApiInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: UserContext,
) -> Optional[BaseResponse]:
    from supertokens_python.auth_utils import load_session_in_auth_api_if_needed
    from supertokens_python.recipe.webauthn.interfaces.api import SignUpPOSTResponse

    if api_implementation.disable_sign_in_post:
        return None

    body = await options.req.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON body")

    webauthn_generated_options_id = body["webauthnGeneratedOptionsId"]
    if webauthn_generated_options_id is None:
        raise_bad_input_exception("webauthnGeneratedOptionsId is required")

    credential = body["credential"]
    if credential is None:
        raise_bad_input_exception("credential is required")

    try:
        # Try to create an object
        # If validation fails, return the response expected from the core.
        # NOTE: Can use `.construct` as an alternative, but the implementation is not stable.
        credential = RegistrationPayload.from_json(credential)
    except ValidationError:
        send_200_response(
            data_json=InvalidCredentialsErrorResponse().to_json(),
            response=options.res,
        )

    should_try_linking_with_session_user = (
        get_normalised_should_try_linking_with_session_user_flag(
            req=options.req, body=body
        )
    )

    session = await load_session_in_auth_api_if_needed(
        request=options.req,
        should_try_linking_with_session_user=should_try_linking_with_session_user,
        user_context=user_context,
    )
    if session is not None:
        tenant_id = session.get_tenant_id()

    result = await api_implementation.sign_up_post(
        webauthn_generated_options_id=webauthn_generated_options_id,
        credential=credential,
        tenant_id=tenant_id,
        session=session,
        should_try_linking_with_session_user=should_try_linking_with_session_user,
        options=options,
        user_context=user_context,
    )
    result_json = result.to_json()

    if result_json["status"] == "OK":
        result = cast(SignUpPOSTResponse, result)
        return send_200_response(
            data_json={
                "status": "OK",
                **get_backwards_compatible_user_info(
                    req=options.req,
                    user_info=result.user,
                    user_context=user_context,
                    session_container=result.session,
                    created_new_recipe_user=None,
                ),
            },
            response=options.res,
        )

    return send_200_response(data_json=result_json, response=options.res)
