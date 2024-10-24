from typing import Any, Dict, Union

from supertokens_python.exceptions import raise_bad_input_exception
from supertokens_python.recipe.emailpassword import EmailPasswordRecipe
from supertokens_python.recipe.emailpassword.interfaces import (
    PasswordPolicyViolationError,
    UnknownUserIdError,
)
from supertokens_python.types import RecipeUserId

from ...interfaces import (
    APIInterface,
    APIOptions,
    UserPasswordPutAPIInvalidPasswordErrorResponse,
    UserPasswordPutAPIResponse,
)


async def handle_user_password_put(
    _api_interface: APIInterface,
    tenant_id: str,
    api_options: APIOptions,
    user_context: Dict[str, Any],
) -> Union[UserPasswordPutAPIResponse, UserPasswordPutAPIInvalidPasswordErrorResponse]:
    request_body: Dict[str, Any] = await api_options.request.json()  # type: ignore
    recipe_user_id = request_body.get("recipeUserId")
    new_password = request_body.get("newPassword")

    if recipe_user_id is None or not isinstance(recipe_user_id, str):
        raise_bad_input_exception("Missing required parameter 'recipeUserId'")

    if new_password is None or not isinstance(new_password, str):
        raise_bad_input_exception("Missing required parameter 'newPassword'")

    email_password_recipe = EmailPasswordRecipe.get_instance()
    update_response = (
        await email_password_recipe.recipe_implementation.update_email_or_password(
            recipe_user_id=RecipeUserId(recipe_user_id),
            email=None,
            password=new_password,
            apply_password_policy=True,
            tenant_id_for_password_policy=tenant_id,
            user_context=user_context,
        )
    )

    if isinstance(update_response, PasswordPolicyViolationError):
        return UserPasswordPutAPIInvalidPasswordErrorResponse(
            error=update_response.failure_reason
        )

    if isinstance(update_response, UnknownUserIdError):
        raise Exception("Should never come here")

    return UserPasswordPutAPIResponse()
