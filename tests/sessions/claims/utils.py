import time as real_time
from typing import Dict, Any, Union, Optional
from unittest.mock import patch

from pytest import mark

from supertokens_python import InputAppInfo, SupertokensConfig
from supertokens_python.framework.request import BaseRequest
from supertokens_python.recipe import session
from supertokens_python.recipe.session import JWTConfig
from supertokens_python.recipe.session.claims import BooleanClaim, SessionClaim
from supertokens_python.recipe.session.interfaces import RecipeInterface

TrueClaim = BooleanClaim("st-true", fetch_value=lambda _, __: True)  # type: ignore
NoneClaim = BooleanClaim("st-none", fetch_value=lambda _, __: None)  # type: ignore


def time_patch_wrapper(fn: Any) -> Any:
    time_patcher = patch(
        "supertokens_python.recipe.session.claim_base_classes.primitive_claim.time",
        wraps=real_time,
    )
    return time_patcher(mark.asyncio(fn))  # type: ignore


def session_functions_override_with_claim(
    claim: SessionClaim[Any], params: Union[Dict[str, Any], None] = None
):
    if params is None:
        params = {}

    def session_function_override(oi: RecipeInterface) -> RecipeInterface:
        oi_create_new_session = oi.create_new_session

        async def new_create_new_session(
            request: BaseRequest,
            user_id: str,
            access_token_payload: Union[None, Dict[str, Any]],
            session_data: Union[None, Dict[str, Any]],
            user_context: Dict[str, Any],
        ):
            payload_update = await claim.build(user_id, user_context)
            if access_token_payload is None:
                access_token_payload = {}
            access_token_payload = {
                **access_token_payload,
                **payload_update,
                **params,
            }

            return await oi_create_new_session(
                request, user_id, access_token_payload, session_data, user_context
            )

        oi.create_new_session = new_create_new_session
        return oi

    return session_function_override


st_init_common_args = {
    "supertokens_config": SupertokensConfig("http://localhost:3567"),
    "app_info": InputAppInfo(
        app_name="ST",
        api_domain="http://api.supertokens.io",
        website_domain="http://supertokens.io",
        api_base_path="/auth",
    ),
    "framework": "fastapi",
    "mode": "asgi",
}

st_init_args_with_TrueClaim = {
    **st_init_common_args,
    "recipe_list": [
        session.init(
            override=session.InputOverrideConfig(
                functions=session_functions_override_with_claim(TrueClaim),
            )
        ),
    ],
}


def get_st_init_args(
    claim: SessionClaim[Any] = TrueClaim, jwt: Optional[JWTConfig] = None
):
    return {
        **st_init_args_with_TrueClaim,
        "recipe_list": [
            session.init(
                override=session.InputOverrideConfig(
                    functions=session_functions_override_with_claim(claim),
                ),
                jwt=jwt,
            ),
        ],
    }
