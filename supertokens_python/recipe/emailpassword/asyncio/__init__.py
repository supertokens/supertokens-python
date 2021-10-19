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
from typing import Union

from deprecated.classic import deprecated

from supertokens_python.recipe.emailpassword import EmailPasswordRecipe


async def create_email_verification_token(user_id: str):
    email = await EmailPasswordRecipe.get_instance().get_email_for_user_id(user_id)
    return await EmailPasswordRecipe.get_instance().email_verification_recipe.recipe_implementation.create_email_verification_token(
        user_id, email)


async def verify_email_using_token(token: str):
    return await EmailPasswordRecipe.get_instance().email_verification_recipe.recipe_implementation.verify_email_using_token(
        token)


async def unverify_email(user_id: str):
    email = await EmailPasswordRecipe.get_instance().get_email_for_user_id(user_id)
    return await EmailPasswordRecipe.get_instance().email_verification_recipe.recipe_implementation.unverify_email(
        user_id, email)


async def is_email_verified(user_id: str):
    email = await EmailPasswordRecipe.get_instance().get_email_for_user_id(user_id)
    return await EmailPasswordRecipe.get_instance().email_verification_recipe.recipe_implementation.is_email_verified(
        user_id, email)


@deprecated(reason="Use supertokens_python.get_user_oldest_first(...) function instead IF using core version >= 3.5")
async def get_users_oldest_first(limit: int = None, next_pagination: str = None):
    return await EmailPasswordRecipe.get_instance().recipe_implementation.get_users_oldest_first(limit, next_pagination)


@deprecated(reason="Use supertokens_python.get_users_newest_first(...) function instead IF using core version >= 3.5")
async def get_users_newest_first(limit: int = None, next_pagination: str = None):
    return await EmailPasswordRecipe.get_instance().recipe_implementation.get_users_newest_first(limit, next_pagination)


@deprecated(reason="Use supertokens_python.get_user_count(...) function instead IF using core version >= 3.5")
async def get_user_count():
    return await EmailPasswordRecipe.get_instance().recipe_implementation.get_user_count()


async def update_email_or_password(user_id: str, email: Union[str, None] = None,
                                   password: Union[str, None] = None):
    return await EmailPasswordRecipe.get_instance().recipe_implementation.update_email_or_password(user_id, email,
                                                                                                   password)


async def get_user_by_id(user_id: str):
    return await EmailPasswordRecipe.get_instance().recipe_implementation.get_user_by_id(user_id)


async def get_user_by_email(email: str):
    return await EmailPasswordRecipe.get_instance().recipe_implementation.get_user_by_email(email)


async def create_reset_password_token(user_id: str):
    return await EmailPasswordRecipe.get_instance().recipe_implementation.create_reset_password_token(user_id)


async def reset_password_using_token(token: str, new_password: str):
    return await EmailPasswordRecipe.get_instance().recipe_implementation.reset_password_using_token(token,
                                                                                                     new_password)


async def sign_in(email: str, password: str):
    return await EmailPasswordRecipe.get_instance().recipe_implementation.sign_in(email, password)


async def sign_up(email: str, password: str):
    return await EmailPasswordRecipe.get_instance().recipe_implementation.sign_up(email, password)


async def revoke_email_verification_token(user_id: str):
    email = await EmailPasswordRecipe.get_instance().get_email_for_user_id(user_id)
    return await EmailPasswordRecipe.get_instance().email_verification_recipe.recipe_implementation.revoke_email_verification_tokens(
        user_id, email)
