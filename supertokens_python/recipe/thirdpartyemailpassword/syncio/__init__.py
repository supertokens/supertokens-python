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
from deprecated.classic import deprecated

from supertokens_python.async_to_sync_wrapper import sync


def create_email_verification_token(user_id: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import create_email_verification_token
    return sync(create_email_verification_token(user_id))


def verify_email_using_token(token: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import verify_email_using_token
    return sync(verify_email_using_token(token))


def is_email_verified(user_id: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import is_email_verified
    return sync(is_email_verified(user_id))


def unverify_email(user_id: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import unverify_email
    return sync(unverify_email(user_id))


@deprecated(reason="Use supertokens_python.get_user_oldest_first(...) function instead IF using core version >= 3.5")
def get_users_oldest_first(limit: int = None, next_pagination: str = None):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import get_users_oldest_first
    return sync(get_users_oldest_first(limit, next_pagination))


@deprecated(reason="Use supertokens_python.get_users_newest_first(...) function instead IF using core version >= 3.5")
def get_users_newest_first(limit: int = None, next_pagination: str = None):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import get_users_newest_first
    return sync(get_users_newest_first(limit, next_pagination))


@deprecated(reason="Use supertokens_python.get_user_count(...) function instead IF using core version >= 3.5")
def get_user_count():
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import get_user_count
    return sync(get_user_count())


def get_user_by_id(user_id: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import get_user_by_id
    return sync(get_user_by_id(user_id))


def get_user_by_third_party_info(
        third_party_id: str, third_party_user_id: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import get_user_by_third_party_info
    return sync(get_user_by_third_party_info(
        third_party_id, third_party_user_id))


def sign_in_up(third_party_id: str, third_party_user_id: str,
               email: str, email_verified: bool):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import sign_in_up
    return sync(sign_in_up(third_party_id,
                           third_party_user_id, email, email_verified))


def create_reset_password_token(user_id: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import create_reset_password_token
    return sync(create_reset_password_token(user_id))


def reset_password_using_token(token: str, new_password: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import reset_password_using_token
    return sync(reset_password_using_token(token, new_password))


def sign_in(email: str, password: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import sign_in
    return sync(sign_in(email, password))


def sign_up(email: str, password: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import sign_up
    return sync(sign_up(email, password))


def update_email_or_password(user_id: str, email: str = None, password: str = None):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import update_email_or_password
    return sync(update_email_or_password(user_id, email, password))


def get_users_by_email(email: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import get_users_by_email
    return sync(get_users_by_email(email))


async def revoke_email_verification_tokens(user_id: str):
    from supertokens_python.recipe.thirdpartyemailpassword.asyncio import revoke_email_verification_tokens
    return sync(revoke_email_verification_tokens(user_id))
