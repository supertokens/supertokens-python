from typing import Optional

from supertokens_python.framework.response import BaseResponse
from supertokens_python.recipe.webauthn.interfaces.api import ApiInterface, APIOptions
from supertokens_python.recipe.webauthn.types.base import UserContext
from supertokens_python.utils import send_200_response


async def sign_in_options_api(
    api_implementation: ApiInterface,
    tenant_id: str,
    options: APIOptions,
    user_context: UserContext,
) -> Optional[BaseResponse]:
    if api_implementation.disable_sign_in_options_post:
        return None

    result = await api_implementation.sign_in_options_post(
        tenant_id=tenant_id, options=options, user_context=user_context
    )

    return send_200_response(data_json=result.to_json(), response=options.res)
