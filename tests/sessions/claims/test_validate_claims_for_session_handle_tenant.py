from typing import Any, Tuple

from supertokens_python import init
from supertokens_python.recipe import emailpassword, multitenancy, session, userroles
from supertokens_python.recipe.emailpassword.asyncio import sign_up
from supertokens_python.recipe.emailpassword.interfaces import SignUpOkResult
from supertokens_python.recipe.multitenancy.asyncio import (
    associate_user_to_tenant,
    create_or_update_tenant,
)
from supertokens_python.recipe.multitenancy.interfaces import (
    TenantConfigCreateOrUpdate,
)
from supertokens_python.recipe.session.asyncio import (
    create_new_session_without_request_response,
    get_session_information,
    validate_claims_for_session_handle,
)
from supertokens_python.recipe.session.interfaces import (
    ClaimsValidationResult,
    SessionContainer,
)
from supertokens_python.recipe.userroles import UserRoleClaim
from supertokens_python.recipe.userroles.asyncio import (
    add_role_to_user,
    create_new_role_or_add_permissions,
)

from tests.utils import get_new_core_app_url, get_st_init_args


async def setup():
    init(
        **get_st_init_args(
            url=get_new_core_app_url(),
            recipe_list=[
                emailpassword.init(),
                multitenancy.init(),
                # roles are not added at session creation, so validating the claim has to fetch them
                userroles.init(
                    skip_adding_roles_to_access_token=True,
                    skip_adding_permissions_to_access_token=True,
                ),
                session.init(get_token_transfer_method=lambda *_: "header"),  # type: ignore
            ],
        )
    )
    await create_or_update_tenant(
        "t1", TenantConfigCreateOrUpdate(first_factors=["emailpassword"])
    )
    await create_new_role_or_add_permissions("admin", [])


async def create_session_in_tenant(tenant_id: str) -> Tuple[Any, SessionContainer]:
    sign_up_res = await sign_up(tenant_id, "user@example.com", "password123")
    assert isinstance(sign_up_res, SignUpOkResult)
    user = sign_up_res.user
    s = await create_new_session_without_request_response(
        tenant_id, user.login_methods[0].recipe_user_id
    )
    return user, s


async def test_claim_value_is_fetched_for_the_session_tenant():
    await setup()
    user, s = await create_session_in_tenant("t1")
    await add_role_to_user("t1", user.id, "admin")

    res = await validate_claims_for_session_handle(
        s.get_handle(),
        lambda _, __, ___: [UserRoleClaim.validators.includes("admin")],
    )

    assert isinstance(res, ClaimsValidationResult)
    assert res.invalid_claims == []

    session_info = await get_session_information(s.get_handle())
    assert session_info is not None
    assert session_info.tenant_id == "t1"
    payload = session_info.custom_claims_in_access_token_payload
    assert UserRoleClaim.get_value_from_payload(payload) == ["admin"]
    assert "tId" not in payload


async def test_roles_of_the_public_tenant_are_not_used_for_a_session_in_another_tenant():
    await setup()
    user, s = await create_session_in_tenant("t1")
    await associate_user_to_tenant("public", user.login_methods[0].recipe_user_id)
    await add_role_to_user("public", user.id, "admin")

    res = await validate_claims_for_session_handle(
        s.get_handle(),
        lambda _, __, ___: [UserRoleClaim.validators.includes("admin")],
    )

    assert isinstance(res, ClaimsValidationResult)
    assert len(res.invalid_claims) == 1
    assert res.invalid_claims[0].id_ == UserRoleClaim.key


async def test_claim_value_is_fetched_for_a_session_in_the_public_tenant():
    await setup()
    user, s = await create_session_in_tenant("public")
    await add_role_to_user("public", user.id, "admin")

    res = await validate_claims_for_session_handle(
        s.get_handle(),
        lambda _, __, ___: [UserRoleClaim.validators.includes("admin")],
    )

    assert isinstance(res, ClaimsValidationResult)
    assert res.invalid_claims == []
