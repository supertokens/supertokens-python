from typing import Any, Dict, Optional, Union

from supertokens_python.recipe import session
from supertokens_python.recipe.session.claims import (
    BooleanClaim,
    SessionClaim,
)
from supertokens_python.recipe.session.interfaces import RecipeInterface
from supertokens_python.types import RecipeUserId

from tests.utils import get_new_core_app_url
from tests.utils import get_st_init_args as base_get_st_init_args

TrueClaim = BooleanClaim("st-true", fetch_value=lambda _, __, ___, _____, ______: True)
NoneClaim = BooleanClaim("st-none", fetch_value=lambda _, __, ___, _____, ______: None)


def session_functions_override_with_claim(
    claim: SessionClaim[Any], params: Union[Dict[str, Any], None] = None
):
    if params is None:
        params = {}

    def session_function_override(oi: RecipeInterface) -> RecipeInterface:
        oi_create_new_session = oi.create_new_session

        async def new_create_new_session(
            user_id: str,
            recipe_user_id: RecipeUserId,
            access_token_payload: Union[None, Dict[str, Any]],
            session_data_in_database: Union[None, Dict[str, Any]],
            disable_anti_csrf: Optional[bool],
            tenant_id: str,
            user_context: Dict[str, Any],
        ):
            if access_token_payload is None:
                access_token_payload = {}
            payload_update = await claim.build(
                user_id,
                RecipeUserId(user_id),
                tenant_id,
                access_token_payload,
                user_context,
            )
            access_token_payload = {
                **access_token_payload,
                **payload_update,
                **params,
            }

            return await oi_create_new_session(
                user_id,
                recipe_user_id,
                access_token_payload,
                session_data_in_database,
                disable_anti_csrf,
                tenant_id,
                user_context,
            )

        oi.create_new_session = new_create_new_session
        return oi

    return session_function_override


def get_st_init_args(claim: SessionClaim[Any] = TrueClaim):
    return base_get_st_init_args(
        url=get_new_core_app_url(),
        recipe_list=[
            session.init(
                override=session.InputOverrideConfig(
                    functions=session_functions_override_with_claim(claim),
                ),
            ),
        ],
    )
