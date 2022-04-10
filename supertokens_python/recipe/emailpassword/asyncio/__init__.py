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
from typing import Any, Dict, Union

from supertokens_python.recipe.emailpassword import EmailPasswordRecipe

from ..types import User


async def create_email_verification_token(user_id: str, user_context: Union[None, Dict[str, Any]] = None):
    """create_email_verification_token.

    Parameters
    ----------
    user_id : str
        user_id
    user_context : Union[None, Dict[str, Any]]
        user_context
    """
    if user_context is None:
        user_context = {}
    email = await EmailPasswordRecipe.get_instance().get_email_for_user_id(user_id, user_context)
    return await EmailPasswordRecipe.get_instance().email_verification_recipe.recipe_implementation.create_email_verification_token(
        user_id, email, user_context)


async def verify_email_using_token(token: str, user_context: Union[None, Dict[str, Any]] = None):
    """verify_email_using_token.

    Parameters
    ----------
    token : str
        token
    user_context : Union[None, Dict[str, Any]]
        user_context
    """
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().email_verification_recipe.recipe_implementation.verify_email_using_token(
        token, user_context)


async def unverify_email(user_id: str, user_context: Union[None, Dict[str, Any]] = None):
    """unverify_email.

    Parameters
    ----------
    user_id : str
        user_id
    user_context : Union[None, Dict[str, Any]]
        user_context
    """
    if user_context is None:
        user_context = {}
    email = await EmailPasswordRecipe.get_instance().get_email_for_user_id(user_id, user_context)
    return await EmailPasswordRecipe.get_instance().email_verification_recipe.recipe_implementation.unverify_email(
        user_id, email, user_context)


async def is_email_verified(user_id: str, user_context: Union[None, Dict[str, Any]] = None):
    """is_email_verified.

    Parameters
    ----------
    user_id : str
        user_id
    user_context : Union[None, Dict[str, Any]]
        user_context
    """
    if user_context is None:
        user_context = {}
    email = await EmailPasswordRecipe.get_instance().get_email_for_user_id(user_id, user_context)
    return await EmailPasswordRecipe.get_instance().email_verification_recipe.recipe_implementation.is_email_verified(
        user_id, email, user_context)


async def update_email_or_password(user_id: str, email: Union[str, None] = None,
                                   password: Union[str, None] = None, user_context: Union[None, Dict[str, Any]] = None):
    """update_email_or_password.

    Parameters
    ----------
    user_id : str
        user_id
    email : Union[str, None]
        email
    password : Union[str, None]
        password
    user_context : Union[None, Dict[str, Any]]
        user_context
    """
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.update_email_or_password(user_id, email, password, user_context)


async def get_user_by_id(user_id: str, user_context: Union[None, Dict[str, Any]] = None) -> Union[None, User]:
    """get_user_by_id.

    Parameters
    ----------
    user_id : str
        user_id
    user_context : Union[None, Dict[str, Any]]
        user_context

    Returns
    -------
    Union[None, User]

    """
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.get_user_by_id(user_id, user_context)


async def get_user_by_email(email: str, user_context: Union[None, Dict[str, Any]] = None) -> Union[User, None]:
    """get_user_by_email.

    Parameters
    ----------
    email : str
        email
    user_context : Union[None, Dict[str, Any]]
        user_context

    Returns
    -------
    Union[User, None]

    """
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.get_user_by_email(email, user_context)


async def create_reset_password_token(user_id: str, user_context: Union[None, Dict[str, Any]] = None):
    """create_reset_password_token.

    Parameters
    ----------
    user_id : str
        user_id
    user_context : Union[None, Dict[str, Any]]
        user_context
    """
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.create_reset_password_token(user_id, user_context)


async def reset_password_using_token(token: str, new_password: str, user_context: Union[None, Dict[str, Any]] = None):
    """reset_password_using_token.

    Parameters
    ----------
    token : str
        token
    new_password : str
        new_password
    user_context : Union[None, Dict[str, Any]]
        user_context
    """
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.reset_password_using_token(token, new_password, user_context)


async def sign_in(email: str, password: str, user_context: Union[None, Dict[str, Any]] = None):
    """sign_in.

    Parameters
    ----------
    email : str
        email
    password : str
        password
    user_context : Union[None, Dict[str, Any]]
        user_context
    """
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.sign_in(email, password, user_context)


async def sign_up(email: str, password: str, user_context: Union[None, Dict[str, Any]] = None):
    """sign_up.

    Parameters
    ----------
    email : str
        email
    password : str
        password
    user_context : Union[None, Dict[str, Any]]
        user_context
    """
    if user_context is None:
        user_context = {}
    return await EmailPasswordRecipe.get_instance().recipe_implementation.sign_up(email, password, user_context)


async def revoke_email_verification_token(user_id: str, user_context: Union[None, Dict[str, Any]] = None):
    """revoke_email_verification_token.

    Parameters
    ----------
    user_id : str
        user_id
    user_context : Union[None, Dict[str, Any]]
        user_context
    """
    if user_context is None:
        user_context = {}
    email = await EmailPasswordRecipe.get_instance().get_email_for_user_id(user_id, user_context)
    return await EmailPasswordRecipe.get_instance().email_verification_recipe.recipe_implementation.revoke_email_verification_tokens(
        user_id, email, user_context)
