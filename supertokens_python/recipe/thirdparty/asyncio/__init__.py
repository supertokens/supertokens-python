# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import Any, Dict, List, Union

from supertokens_python.recipe.thirdparty.recipe import ThirdPartyRecipe

from ..types import EmailTemplateVars, User


async def create_email_verification_token(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    email = await ThirdPartyRecipe.get_instance().get_email_for_user_id(
        user_id, user_context
    )
    return await ThirdPartyRecipe.get_instance().email_verification_recipe.recipe_implementation.create_email_verification_token(
        user_id, email, user_context
    )


async def verify_email_using_token(
    token: str, user_context: Union[None, Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    return await ThirdPartyRecipe.get_instance().email_verification_recipe.recipe_implementation.verify_email_using_token(
        token, user_context
    )


async def is_email_verified(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    email = await ThirdPartyRecipe.get_instance().get_email_for_user_id(
        user_id, user_context
    )
    return await ThirdPartyRecipe.get_instance().email_verification_recipe.recipe_implementation.is_email_verified(
        user_id, email, user_context
    )


async def unverify_email(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    email = await ThirdPartyRecipe.get_instance().get_email_for_user_id(
        user_id, user_context
    )
    return await ThirdPartyRecipe.get_instance().email_verification_recipe.recipe_implementation.unverify_email(
        user_id, email, user_context
    )


async def revoke_email_verification_tokens(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    email = await ThirdPartyRecipe.get_instance().get_email_for_user_id(
        user_id, user_context
    )
    return await ThirdPartyRecipe.get_instance().email_verification_recipe.recipe_implementation.revoke_email_verification_tokens(
        user_id, email, user_context
    )


async def get_user_by_id(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[User, None]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyRecipe.get_instance().recipe_implementation.get_user_by_id(
        user_id, user_context
    )


async def get_users_by_email(
    email: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[User]:
    if user_context is None:
        user_context = {}
    return (
        await ThirdPartyRecipe.get_instance().recipe_implementation.get_users_by_email(
            email, user_context
        )
    )


async def get_user_by_third_party_info(
    third_party_id: str,
    third_party_user_id: str,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await ThirdPartyRecipe.get_instance().recipe_implementation.get_user_by_thirdparty_info(
        third_party_id, third_party_user_id, user_context
    )


async def sign_in_up(
    third_party_id: str,
    third_party_user_id: str,
    email: str,
    email_verified: bool,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await ThirdPartyRecipe.get_instance().recipe_implementation.sign_in_up(
        third_party_id, third_party_user_id, email, email_verified, user_context
    )


async def send_email(
    input_: EmailTemplateVars, user_context: Union[None, Dict[str, Any]] = None
):
    if user_context is None:
        user_context = {}
    return await ThirdPartyRecipe.get_instance().email_delivery.ingredient_interface_impl.send_email(
        input_, user_context
    )
