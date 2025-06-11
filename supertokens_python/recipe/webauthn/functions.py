# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from typing import List, Optional, Union, cast

from typing_extensions import Unpack

from supertokens_python import get_request_from_user_context
from supertokens_python.async_to_sync_wrapper import syncify
from supertokens_python.asyncio import get_user
from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.recipe.webauthn.interfaces.api import (
    TypeWebauthnRecoverAccountEmailDeliveryInput,
    WebauthnRecoverAccountEmailDeliveryUser,
)
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    Attestation,
    AuthenticationPayload,
    ConsumeRecoverAccountTokenErrorResponse,
    CreateRecoverAccountLinkResponse,
    RegisterCredentialErrorResponse,
    RegisterOptionsKwargsInput,
    RegistrationPayload,
    ResidentKey,
    UnknownUserIdErrorResponse,
    UserVerification,
)
from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe
from supertokens_python.recipe.webauthn.utils import get_recover_account_link
from supertokens_python.types.base import LoginMethod, UserContext
from supertokens_python.types.response import (
    OkResponseBaseModel,
    StatusResponseBaseModel,
)


@syncify
async def register_options(
    *,
    relying_party_id: str,
    relying_party_name: str,
    origin: str,
    resident_key: Optional[ResidentKey] = None,
    user_verification: Optional[UserVerification] = None,
    user_presence: Optional[bool] = None,
    attestation: Optional[Attestation] = None,
    supported_algorithm_ids: Optional[List[int]] = None,
    timeout: Optional[int] = None,
    tenant_id: str = DEFAULT_TENANT_ID,
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
    timeout: Optional[int] = None,
    user_verification: Optional[UserVerification] = None,
    user_presence: Optional[bool] = None,
    tenant_id: str = DEFAULT_TENANT_ID,
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
    tenant_id: str = DEFAULT_TENANT_ID,
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
    tenant_id: str = DEFAULT_TENANT_ID,
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
    tenant_id: str = DEFAULT_TENANT_ID,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    response = (
        await WebauthnRecipe.get_instance().recipe_implementation.verify_credentials(
            credential=credential,
            webauthn_generated_options_id=webauthn_generated_options_id,
            tenant_id=tenant_id,
            user_context=user_context,
        )
    )

    # Here we intentionally skip the user and recipeUserId props, because we
    # do not want apps to accidentally use this to sign in
    return StatusResponseBaseModel(status=response.status)


@syncify
async def create_new_recipe_user(
    *,
    credential: RegistrationPayload,
    webauthn_generated_options_id: str,
    tenant_id: str = DEFAULT_TENANT_ID,
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


# We do not make email optional here because we want to
# allow passing in primaryUserId. If we make email optional,
# and if the user provides a primaryUserId, then it may result in two problems:
#  - there is no recipeUserId = input primaryUserId, in this case,
#    this function will throw an error
#  - There is a recipe userId = input primaryUserId, but that recipe has no email,
#    or has wrong email compared to what the user wanted to generate a reset token for.
#
# And we want to allow primaryUserId being passed in.
@syncify
async def generate_recover_account_token(
    *,
    user_id: str,
    email: str,
    tenant_id: str = DEFAULT_TENANT_ID,
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
    tenant_id: str = DEFAULT_TENANT_ID,
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
    tenant_id: str = DEFAULT_TENANT_ID,
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
    tenant_id: str = DEFAULT_TENANT_ID,
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
    tenant_id: str = DEFAULT_TENANT_ID,
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
    tenant_id: str = DEFAULT_TENANT_ID,
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


@syncify
async def recover_account(
    *,
    tenant_id: str = DEFAULT_TENANT_ID,
    webauthn_generated_options_id: str,
    token: str,
    credential: RegistrationPayload,
    user_context: Optional[UserContext] = None,
) -> Union[
    OkResponseBaseModel,
    ConsumeRecoverAccountTokenErrorResponse,
    RegisterCredentialErrorResponse,
]:
    consume_response = await consume_recover_account_token(
        tenant_id=tenant_id,
        token=token,
        user_context=user_context,
    )

    if consume_response.status != "OK":
        return consume_response

    result = await register_credential(
        recipe_user_id=consume_response.user_id,
        webauthn_generated_options_id=webauthn_generated_options_id,
        credential=credential,
        user_context=user_context,
    )

    return result


@syncify
async def create_recover_account_link(
    *,
    tenant_id: str = DEFAULT_TENANT_ID,
    user_id: str,
    email: str,
    user_context: Optional[UserContext] = None,
) -> Union[CreateRecoverAccountLinkResponse, UnknownUserIdErrorResponse]:
    if user_context is None:
        user_context = {}

    token_response = await generate_recover_account_token(
        user_id=user_id,
        email=email,
        tenant_id=tenant_id,
        user_context=user_context,
    )
    if isinstance(token_response, UnknownUserIdErrorResponse):
        return token_response

    recipe_instance = WebauthnRecipe.get_instance()
    link = get_recover_account_link(
        app_info=recipe_instance.get_app_info(),
        token=token_response.token,
        tenant_id=tenant_id,
        request=get_request_from_user_context(user_context),
        user_context=user_context,
    )

    return CreateRecoverAccountLinkResponse(link=link)


@syncify
async def send_email(
    *,
    template_vars: TypeWebauthnRecoverAccountEmailDeliveryInput,
    user_context: Optional[UserContext] = None,
):
    if user_context is None:
        user_context = {}

    recipe_instance = WebauthnRecipe.get_instance()
    return await recipe_instance.email_delivery.ingredient_interface_impl.send_email(
        template_vars=template_vars,
        user_context=user_context,
    )


@syncify
async def send_recover_account_email(
    *,
    tenant_id: str = DEFAULT_TENANT_ID,
    user_id: str,
    email: str,
    user_context: Optional[UserContext] = None,
) -> Union[OkResponseBaseModel, UnknownUserIdErrorResponse]:
    user = await get_user(user_id=user_id, user_context=user_context)
    if user is None:
        return UnknownUserIdErrorResponse()

    login_method: Optional[LoginMethod] = None
    for lm in user.login_methods:
        if lm.recipe_id == "webauthn" and lm.has_same_email_as(email):
            login_method = lm
            break

    if login_method is None:
        return UnknownUserIdErrorResponse()

    link_response = await create_recover_account_link(
        tenant_id=tenant_id,
        user_id=user_id,
        email=email,
        user_context=user_context,
    )
    if link_response.status != "OK":
        return link_response

    await send_email(
        template_vars=TypeWebauthnRecoverAccountEmailDeliveryInput(
            user=WebauthnRecoverAccountEmailDeliveryUser(
                id=user.id,
                recipe_user_id=login_method.recipe_user_id,
                email=cast(str, login_method.email),
            ),
            recover_account_link=link_response.link,
            tenant_id=tenant_id,
        ),
    )

    return OkResponseBaseModel()
