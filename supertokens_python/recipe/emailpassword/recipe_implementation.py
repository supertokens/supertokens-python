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
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Union

from supertokens_python.normalised_url_path import NormalisedURLPath

from .interfaces import (CreateResetPasswordOkResult,
                         CreateResetPasswordWrongUserIdErrorResult,
                         RecipeInterface, ResetPasswordUsingTokenOkResult,
                         ResetPasswordUsingTokenWrongUserIdErrorResult,
                         SignInOkResult, SignInWrongCredentialsErrorResult,
                         SignUpEmailAlreadyExistsErrorResult, SignUpOkResult,
                         UpdateEmailOrPasswordEmailAlreadyExistsErrorResult,
                         UpdateEmailOrPasswordOkResult,
                         UpdateEmailOrPasswordUnknownUserIdErrorResult)
from .types import User

if TYPE_CHECKING:
    from supertokens_python.querier import Querier

    from .interfaces import (CreateResetPasswordResult,
                             ResetPasswordUsingTokenResult, SignInResult,
                             SignUpResult, UpdateEmailOrPasswordResult)


class RecipeImplementation(RecipeInterface):
    """RecipeImplementation.
    """

    def __init__(self, querier: Querier):
        """__init__.

        Parameters
        ----------
        querier : Querier
            querier
        """
        super().__init__()
        self.querier = querier

    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        """get_user_by_id.

        Parameters
        ----------
        user_id : str
            user_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[User, None]

        """
        params = {
            'userId': user_id
        }
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/user'), params)
        if 'status' in response and response['status'] == 'OK':
            return User(response['user']['id'], response['user']
                        ['email'], response['user']['timeJoined'])
        return None

    async def get_user_by_email(self, email: str, user_context: Dict[str, Any]) -> Union[User, None]:
        """get_user_by_email.

        Parameters
        ----------
        email : str
            email
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[User, None]

        """
        params = {
            'email': email
        }
        response = await self.querier.send_get_request(NormalisedURLPath('/recipe/user'), params)
        if 'status' in response and response['status'] == 'OK':
            return User(response['user']['id'], response['user']
                        ['email'], response['user']['timeJoined'])
        return None

    async def create_reset_password_token(self, user_id: str, user_context: Dict[str, Any]) -> CreateResetPasswordResult:
        """create_reset_password_token.

        Parameters
        ----------
        user_id : str
            user_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        CreateResetPasswordResult

        """
        data = {
            'userId': user_id
        }
        response = await self.querier.send_post_request(
            NormalisedURLPath('/recipe/user/password/reset/token'),
            data)
        if 'status' in response and response['status'] == 'OK':
            return CreateResetPasswordOkResult(response['token'])
        return CreateResetPasswordWrongUserIdErrorResult()

    async def reset_password_using_token(self, token: str, new_password: str, user_context: Dict[str, Any]) -> ResetPasswordUsingTokenResult:
        """reset_password_using_token.

        Parameters
        ----------
        token : str
            token
        new_password : str
            new_password
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        ResetPasswordUsingTokenResult

        """
        data = {
            'method': 'token',
            'token': token,
            'newPassword': new_password
        }
        response = await self.querier.send_post_request(
            NormalisedURLPath('/recipe/user/password/reset'), data)
        if 'status' not in response or response['status'] != 'OK':
            return ResetPasswordUsingTokenWrongUserIdErrorResult()
        user_id = None
        if 'userId' in response:
            user_id = response['userId']
        return ResetPasswordUsingTokenOkResult(user_id)

    async def sign_in(self, email: str, password: str, user_context: Dict[str, Any]) -> SignInResult:
        """sign_in.

        Parameters
        ----------
        email : str
            email
        password : str
            password
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignInResult

        """
        data = {
            'password': password,
            'email': email
        }
        response = await self.querier.send_post_request(NormalisedURLPath('/recipe/signin'), data)
        if 'status' in response and response['status'] == 'OK':
            return SignInOkResult(
                User(response['user']['id'], response['user']['email'], response['user']['timeJoined']))
        return SignInWrongCredentialsErrorResult()

    async def sign_up(self, email: str, password: str, user_context: Dict[str, Any]) -> SignUpResult:
        """sign_up.

        Parameters
        ----------
        email : str
            email
        password : str
            password
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignUpResult

        """
        data = {
            'password': password,
            'email': email
        }
        response = await self.querier.send_post_request(NormalisedURLPath('/recipe/signup'), data)
        if 'status' in response and response['status'] == 'OK':
            return SignUpOkResult(
                User(response['user']['id'], response['user']['email'], response['user']['timeJoined']))
        return SignUpEmailAlreadyExistsErrorResult()

    async def update_email_or_password(self, user_id: str, email: Union[str, None],
                                       password: Union[str, None], user_context: Dict[str, Any]) -> UpdateEmailOrPasswordResult:
        """update_email_or_password.

        Parameters
        ----------
        user_id : str
            user_id
        email : Union[str, None]
            email
        password : Union[str, None]
            password
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        UpdateEmailOrPasswordResult

        """
        data = {
            'userId': user_id
        }
        if email is not None:
            data = {
                'email': email,
                **data
            }
        if password is not None:
            data = {
                'password': password,
                **data
            }
        response = await self.querier.send_put_request(NormalisedURLPath('/recipe/user'), data)
        if 'status' in response and response['status'] == 'OK':
            return UpdateEmailOrPasswordOkResult()
        if 'status' in response and response['status'] == 'EMAIL_ALREADY_EXISTS_ERROR':
            return UpdateEmailOrPasswordEmailAlreadyExistsErrorResult()
        return UpdateEmailOrPasswordUnknownUserIdErrorResult()
