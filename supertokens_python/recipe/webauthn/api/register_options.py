from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework.response import BaseResponse
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    InvalidEmailErrorResponse,
)
from supertokens_python.types.base import UserContext
from supertokens_python.utils import send_200_response

if TYPE_CHECKING:
    from supertokens_python.recipe.webauthn.interfaces.api import (
        APIInterface,
        APIOptions,
    )


async def register_options_api(
    api_implementation: APIInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: UserContext,
) -> Optional[BaseResponse]:
    if api_implementation.disable_register_options_post:
        return None

    body = await options.req.json()
    if body is None:
        raise_bad_input_exception("Please provide a JSON body")

    email = body.get("email")
    recover_account_token = body.get("recoverAccountToken")

    if (email is None or not isinstance(email, str)) and (
        recover_account_token is None or not isinstance(recover_account_token, str)
    ):
        raise_bad_input_exception(
            "Please provide the email or the recover account token"
        )

    if email is not None:
        email = email.strip()
        validate_error = await options.config.validate_email_address(
            email=email, tenant_id=tenant_id, user_context=user_context
        )
        if validate_error is not None:
            return send_200_response(
                data_json=InvalidEmailErrorResponse(err=validate_error).to_json(),
                response=options.res,
            )

    result = await api_implementation.register_options_post(
        email=email,
        recover_account_token=recover_account_token,
        tenant_id=tenant_id,
        options=options,
        user_context=user_context,
    )
    result_json = result.to_json()

    return send_200_response(data_json=result_json, response=options.res)
