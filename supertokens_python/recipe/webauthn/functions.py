from typing import List, Optional

from typing_extensions import Unpack

from supertokens_python.async_to_sync_wrapper import syncify
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    Attestation,
    AuthenticationPayload,
    RegisterOptionsKwargsInput,
    RegistrationPayload,
    ResidentKey,
    UserVerification,
)
from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe
from supertokens_python.recipe.webauthn.types.base import UserContext


@syncify
async def register_options(
    *,
    relying_party_id: str,
    relying_party_name: str,
    origin: str,
    resident_key: Optional[ResidentKey],
    user_verification: Optional[UserVerification],
    user_presence: Optional[bool],
    attestation: Optional[Attestation],
    supported_algorithm_ids: Optional[List[int]],
    timeout: Optional[int],
    tenant_id: str,
    user_context: Optional[UserContext] = None,
    **kwargs: Unpack[RegisterOptionsKwargsInput],
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.register_options(
        relying_party_id=relying_party_id,
        relying_party_name=relying_party_name,
        origin=origin,
        resident_key=resident_key,
        user_verification=user_verification,
        user_presence=user_presence,
        attestation=attestation,
        supported_algorithm_ids=supported_algorithm_ids,
        timeout=timeout,
        tenant_id=tenant_id,
        user_context=user_context,
        **kwargs,
    )


@syncify
async def sign_in_options(
    *,
    relying_party_id: str,
    relying_party_name: str,
    origin: str,
    timeout: Optional[int],
    user_verification: Optional[UserVerification],
    user_presence: Optional[bool],
    tenant_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.sign_in_options(
        relying_party_id=relying_party_id,
        relying_party_name=relying_party_name,
        origin=origin,
        timeout=timeout,
        user_verification=user_verification,
        user_presence=user_presence,
        tenant_id=tenant_id,
        user_context=user_context,
    )


@syncify
async def sign_up(
    *,
    webauthn_generated_options_id: str,
    credential: RegistrationPayload,
    tenant_id: str,
    session: Optional[SessionContainer] = None,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.sign_up(
        webauthn_generated_options_id=webauthn_generated_options_id,
        credential=credential,
        tenant_id=tenant_id,
        session=session,
        should_try_linking_with_session_user=session is not None,
        user_context=user_context,
    )


@syncify
async def sign_in(
    *,
    credential: AuthenticationPayload,
    webauthn_generated_options_id: str,
    tenant_id: str,
    session: Optional[SessionContainer] = None,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.sign_in(
        credential=credential,
        webauthn_generated_options_id=webauthn_generated_options_id,
        tenant_id=tenant_id,
        session=session,
        should_try_linking_with_session_user=session is not None,
        user_context=user_context,
    )


@syncify
async def verify_credentials(
    *,
    credential: AuthenticationPayload,
    webauthn_generated_options_id: str,
    tenant_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.verify_credentials(
        credential=credential,
        webauthn_generated_options_id=webauthn_generated_options_id,
        tenant_id=tenant_id,
        user_context=user_context,
    )


@syncify
async def create_new_recipe_user(
    *,
    credential: RegistrationPayload,
    webauthn_generated_options_id: str,
    tenant_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.create_new_recipe_user(
        credential=credential,
        webauthn_generated_options_id=webauthn_generated_options_id,
        tenant_id=tenant_id,
        user_context=user_context,
    )


@syncify
async def generate_recover_account_token(
    *,
    user_id: str,
    email: str,
    tenant_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.generate_recover_account_token(
        user_id=user_id,
        email=email,
        tenant_id=tenant_id,
        user_context=user_context,
    )


@syncify
async def consume_recover_account_token(
    *,
    token: str,
    tenant_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.consume_recover_account_token(
        token=token,
        tenant_id=tenant_id,
        user_context=user_context,
    )


@syncify
async def register_credential(
    *,
    webauthn_generated_options_id: str,
    credential: RegistrationPayload,
    recipe_user_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return (
        await WebauthnRecipe.get_instance().recipe_implementation.register_credential(
            webauthn_generated_options_id=webauthn_generated_options_id,
            credential=credential,
            recipe_user_id=recipe_user_id,
            user_context=user_context,
        )
    )


@syncify
async def get_user_from_recover_account_token(
    *,
    token: str,
    tenant_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.get_user_from_recover_account_token(
        token=token,
        tenant_id=tenant_id,
        user_context=user_context,
    )


@syncify
async def remove_credential(
    *,
    webauthn_credential_id: str,
    recipe_user_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.remove_credential(
        webauthn_credential_id=webauthn_credential_id,
        recipe_user_id=recipe_user_id,
        user_context=user_context,
    )


@syncify
async def get_credential(
    *,
    webauthn_credential_id: str,
    recipe_user_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.get_credential(
        webauthn_credential_id=webauthn_credential_id,
        recipe_user_id=recipe_user_id,
        user_context=user_context,
    )


@syncify
async def list_credentials(
    *,
    recipe_user_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.list_credentials(
        recipe_user_id=recipe_user_id,
        user_context=user_context,
    )


@syncify
async def remove_generated_options(
    *,
    webauthn_generated_options_id: str,
    tenant_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.remove_generated_options(
        webauthn_generated_options_id=webauthn_generated_options_id,
        tenant_id=tenant_id,
        user_context=user_context,
    )


@syncify
async def get_generated_options(
    *,
    webauthn_generated_options_id: str,
    tenant_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return (
        await WebauthnRecipe.get_instance().recipe_implementation.get_generated_options(
            webauthn_generated_options_id=webauthn_generated_options_id,
            tenant_id=tenant_id,
            user_context=user_context,
        )
    )


@syncify
async def update_user_email(
    *,
    email: str,
    recipe_user_id: str,
    tenant_id: str,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    return await WebauthnRecipe.get_instance().recipe_implementation.update_user_email(
        email=email,
        recipe_user_id=recipe_user_id,
        tenant_id=tenant_id,
        user_context=user_context,
    )
