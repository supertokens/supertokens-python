from typing import Optional

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.framework.response import BaseResponse
from supertokens_python.recipe.webauthn.interfaces.api import ApiInterface, APIOptions
from supertokens_python.recipe.webauthn.types.base import UserContext
from supertokens_python.utils import send_200_response


async def email_exists_api(
    api_implementation: ApiInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: UserContext,
) -> Optional[BaseResponse]:
    if api_implementation.disable_email_exists_get:
        return None

    email = options.req.get_query_param("email")

    if email is None:
        raise_bad_input_exception("Please provide the email as a GET param")

    result = await api_implementation.email_exists_get(
        email=email, tenant_id=tenant_id, options=options, user_context=user_context
    )

    return send_200_response(data_json=result.to_json(), response=options.res)
