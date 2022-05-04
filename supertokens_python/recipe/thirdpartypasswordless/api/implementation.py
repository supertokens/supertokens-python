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
from ...passwordless.interfaces import (CreateCodePostOkResponse,
                                        CreateCodePostGeneralErrorResponse,
                                        EmailExistsGetOkResponse,
                                        PhoneNumberExistsGetOkResponse,
                                        ConsumeCodePostExpiredUserInputCodeErrorResponse,
                                        ConsumeCodePostGeneralErrorResponse,
                                        ConsumeCodePostIncorrectUserInputCodeErrorResponse,
                                        ConsumeCodePostOkResponse,
                                        ConsumeCodePostRestartFlowErrorResponse,
                                        ResendCodePostOkResponse,
                                        ResendCodePostRestartFlowErrorResponse,
                                        ResendCodePostGeneralErrorResponse)
from ...thirdparty.api.implementation import \
    APIImplementation as ThirdPartyImplementation
from ...thirdparty.interfaces import APIOptions as ThirdPartyAPIOptions
from ...thirdparty.interfaces import (AuthorisationUrlGetOkResponse,
                                      SignInUpPostOkResponse,
                                      SignInUpPostNoEmailGivenByProviderResponse,
                                      SignInUpPostFieldErrorResponse)
from ...thirdparty.provider import Provider
from ..interfaces import APIInterface

from .passwordless_api_impementation import \
    get_interface_impl as get_pless_interface_impl
from .thirdparty_api_implementation import \
    get_interface_impl as get_tp_interface_impl


class APIImplementation(APIInterface):
    def __init__(self):
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
                                    api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]) -> AuthorisationUrlGetOkResponse:
        return await self.tp_authorisation_url_get(provider, api_options, user_context)

    async def thirdparty_sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None], auth_code_response: Union[Dict[str, Any], None],
                                         api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]) -> Union[SignInUpPostOkResponse, SignInUpPostNoEmailGivenByProviderResponse, SignInUpPostFieldErrorResponse]:
        return await self.tp_sign_in_up_post(provider, code, redirect_uri, client_id, auth_code_response, api_options, user_context)

    async def apple_redirect_handler_post(self, code: str, state: str,
                                          api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]):
        return await self.tp_apple_redirect_handler_post(code, state, api_options, user_context)

    async def create_code_post(self,
                               email: Union[str, None],
                               phone_number: Union[str, None],
                               api_options: PasswordlessAPIOptions,
                               user_context: Dict[str, Any]) -> Union[CreateCodePostOkResponse, CreateCodePostGeneralErrorResponse]:
        return await self.pless_create_code_post(email, phone_number, api_options, user_context)

    async def resend_code_post(self,
                               device_id: str,
                               pre_auth_session_id: str,
                               api_options: PasswordlessAPIOptions,
                               user_context: Dict[str, Any]) -> Union[ResendCodePostOkResponse, ResendCodePostRestartFlowErrorResponse, ResendCodePostGeneralErrorResponse]:
        return await self.resend_code_post(device_id, pre_auth_session_id, api_options, user_context)

    async def consume_code_post(self,
                                pre_auth_session_id: str,
                                user_input_code: Union[str, None],
                                device_id: Union[str, None],
                                link_code: Union[str, None],
                                api_options: PasswordlessAPIOptions,
                                user_context: Dict[str, Any]) -> Union[ConsumeCodePostOkResponse, ConsumeCodePostRestartFlowErrorResponse, ConsumeCodePostGeneralErrorResponse, ConsumeCodePostIncorrectUserInputCodeErrorResponse, ConsumeCodePostExpiredUserInputCodeErrorResponse]:
        return await self.pless_consume_code_post(pre_auth_session_id, user_input_code, device_id, link_code, api_options, user_context)

    async def passwordless_user_email_exists_get(self,
                                                 email: str,
                                                 api_options: PasswordlessAPIOptions,
                                                 user_context: Dict[str, Any]) -> EmailExistsGetOkResponse:
        return await self.passwordless_user_email_exists_get(email, api_options, user_context)

    async def passwordless_user_phone_number_exists_get(self,
                                                        phone_number: str,
                                                        api_options: PasswordlessAPIOptions,
                                                        user_context: Dict[str, Any]) -> PhoneNumberExistsGetOkResponse:
        return await self.passwordless_user_phone_number_exists_get(phone_number, api_options, user_context)
