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

from typing import Any, Dict, Union

from ...passwordless.api.implementation import \
    APIImplementation as PasswordlessImplementation
from ...passwordless.interfaces import APIInterface
from ...passwordless.interfaces import APIOptions as PasswordlessAPIOptions
from ...passwordless.interfaces import (CreateCodePostResponse,
                                        EmailExistsGetResponse,
                                        PhoneNumberExistsGetResponse,
                                        ResendCodePostResponse)
from ...thirdparty.api.implementation import \
    APIImplementation as ThirdPartyImplementation
from ...thirdparty.interfaces import APIOptions as ThirdPartyAPIOptions
from ...thirdparty.interfaces import (AuthorisationUrlGetResponse,
                                      SignInUpPostResponse)
from ...thirdparty.provider import Provider
from ..interfaces import (APIInterface,
                          ConsumeCodePostExpiredUserInputCodeErrorResponse,
                          ConsumeCodePostGeneralErrorResponse,
                          ConsumeCodePostIncorrectUserInputCodeErrorResponse,
                          ConsumeCodePostOkResponse, ConsumeCodePostResponse,
                          ConsumeCodePostRestartFlowErrorResponse)
from ..types import User
from .passwordless_api_impementation import \
    get_interface_impl as get_pless_interface_impl
from .thirdparty_api_implementation import \
    get_interface_impl as get_tp_interface_impl


class APIImplementation(APIInterface):
    """APIImplementation.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__()
        passwordless_implementation = PasswordlessImplementation()
        self.pless_email_exists_get = passwordless_implementation.email_exists_get
        self.pless_consume_code_post = passwordless_implementation.consume_code_post
        self.pless_create_code_post = passwordless_implementation.create_code_post
        self.pless_phone_number_exists_get = passwordless_implementation.phone_number_exists_get
        self.pless_resend_code_post = passwordless_implementation.resend_code_post
        derived_pless = get_pless_interface_impl(self)
        passwordless_implementation.email_exists_get = derived_pless.email_exists_get
        passwordless_implementation.create_code_post = derived_pless.create_code_post
        passwordless_implementation.consume_code_post = derived_pless.consume_code_post
        passwordless_implementation.phone_number_exists_get = derived_pless.phone_number_exists_get
        passwordless_implementation.resend_code_post = derived_pless.resend_code_post

        thirdparty_implementation = ThirdPartyImplementation()
        self.tp_authorisation_url_get = thirdparty_implementation.authorisation_url_get
        self.tp_sign_in_up_post = thirdparty_implementation.sign_in_up_post
        self.tp_apple_redirect_handler_post = thirdparty_implementation.apple_redirect_handler_post
        derived_tp = get_tp_interface_impl(self)
        thirdparty_implementation.authorisation_url_get = derived_tp.authorisation_url_get
        thirdparty_implementation.sign_in_up_post = derived_tp.sign_in_up_post
        thirdparty_implementation.apple_redirect_handler_post = derived_tp.apple_redirect_handler_post

    async def authorisation_url_get(self, provider: Provider,
                                    api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]) -> AuthorisationUrlGetResponse:
        """authorisation_url_get.

        Parameters
        ----------
        provider : Provider
            provider
        api_options : ThirdPartyAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        AuthorisationUrlGetResponse

        """
        return await self.tp_authorisation_url_get(provider, api_options, user_context)

    async def thirdparty_sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None], auth_code_response: Union[Dict[str, Any], None],
                                         api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]) -> SignInUpPostResponse:
        """thirdparty_sign_in_up_post.

        Parameters
        ----------
        provider : Provider
            provider
        code : str
            code
        redirect_uri : str
            redirect_uri
        client_id : Union[str, None]
            client_id
        auth_code_response : Union[Dict[str, Any], None]
            auth_code_response
        api_options : ThirdPartyAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignInUpPostResponse

        """
        return await self.tp_sign_in_up_post(provider, code, redirect_uri, client_id, auth_code_response, api_options, user_context)

    async def apple_redirect_handler_post(self, code: str, state: str,
                                          api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]):
        """apple_redirect_handler_post.

        Parameters
        ----------
        code : str
            code
        state : str
            state
        api_options : ThirdPartyAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context
        """
        return await self.tp_apple_redirect_handler_post(code, state, api_options, user_context)

    async def create_code_post(self,
                               email: Union[str, None],
                               phone_number: Union[str, None],
                               api_options: PasswordlessAPIOptions,
                               user_context: Dict[str, Any]) -> CreateCodePostResponse:
        """create_code_post.

        Parameters
        ----------
        email : Union[str, None]
            email
        phone_number : Union[str, None]
            phone_number
        api_options : PasswordlessAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        CreateCodePostResponse

        """
        return await self.pless_create_code_post(email, phone_number, api_options, user_context)

    async def resend_code_post(self,
                               device_id: str,
                               pre_auth_session_id: str,
                               api_options: PasswordlessAPIOptions,
                               user_context: Dict[str, Any]) -> ResendCodePostResponse:
        """resend_code_post.

        Parameters
        ----------
        device_id : str
            device_id
        pre_auth_session_id : str
            pre_auth_session_id
        api_options : PasswordlessAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        ResendCodePostResponse

        """
        return await self.resend_code_post(device_id, pre_auth_session_id, api_options, user_context)

    async def consume_code_post(self,
                                pre_auth_session_id: str,
                                user_input_code: Union[str, None],
                                device_id: Union[str, None],
                                link_code: Union[str, None],
                                api_options: PasswordlessAPIOptions,
                                user_context: Dict[str, Any]) -> ConsumeCodePostResponse:
        """consume_code_post.

        Parameters
        ----------
        pre_auth_session_id : str
            pre_auth_session_id
        user_input_code : Union[str, None]
            user_input_code
        device_id : Union[str, None]
            device_id
        link_code : Union[str, None]
            link_code
        api_options : PasswordlessAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        ConsumeCodePostResponse

        """
        otherType = await self.pless_consume_code_post(pre_auth_session_id, user_input_code, device_id, link_code, api_options, user_context)
        if otherType.is_ok:
            if otherType.created_new_user is None or otherType.user is None or otherType.session is None:
                raise Exception("Should never come here")
            return ConsumeCodePostOkResponse(otherType.created_new_user, User(otherType.user.user_id, otherType.user.email, otherType.user.phone_number, None, otherType.user.time_joined), otherType.session)
        if otherType.is_expired_user_input_code_error:
            if otherType.failed_code_input_attempt_count is None or otherType.maximum_code_input_attempts is None:
                raise Exception("Should never come here")
            return ConsumeCodePostExpiredUserInputCodeErrorResponse(otherType.failed_code_input_attempt_count, otherType.maximum_code_input_attempts)
        if otherType.is_general_error:
            if otherType.message is None:
                raise Exception("Should never come here")
            return ConsumeCodePostGeneralErrorResponse(otherType.message)
        if otherType.is_incorrect_user_input_code_error:
            if otherType.failed_code_input_attempt_count is None or otherType.maximum_code_input_attempts is None:
                raise Exception("Should never come here")
            return ConsumeCodePostIncorrectUserInputCodeErrorResponse(otherType.failed_code_input_attempt_count, otherType.maximum_code_input_attempts)

        # restart flow error
        return ConsumeCodePostRestartFlowErrorResponse()

    async def passwordless_user_email_exists_get(self,
                                                 email: str,
                                                 api_options: PasswordlessAPIOptions,
                                                 user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        """passwordless_user_email_exists_get.

        Parameters
        ----------
        email : str
            email
        api_options : PasswordlessAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        EmailExistsGetResponse

        """
        return await self.passwordless_user_email_exists_get(email, api_options, user_context)

    async def passwordless_user_phone_number_exists_get(self,
                                                        phone_number: str,
                                                        api_options: PasswordlessAPIOptions,
                                                        user_context: Dict[str, Any]) -> PhoneNumberExistsGetResponse:
        """passwordless_user_phone_number_exists_get.

        Parameters
        ----------
        phone_number : str
            phone_number
        api_options : PasswordlessAPIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        PhoneNumberExistsGetResponse

        """
        return await self.passwordless_user_phone_number_exists_get(phone_number, api_options, user_context)
