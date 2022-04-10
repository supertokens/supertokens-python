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

from typing import Any, Dict, List, Union

from supertokens_python.recipe.emailpassword.api.implementation import \
    APIImplementation as EmailPasswordImplementation
from supertokens_python.recipe.emailpassword.interfaces import \
    APIOptions as EmailPasswordApiOptions
from supertokens_python.recipe.emailpassword.interfaces import (
    EmailExistsGetResponse, GeneratePasswordResetTokenPostResponse,
    PasswordResetPostResponse, SignInPostResponse, SignUpPostResponse)
from supertokens_python.recipe.emailpassword.types import FormField
from supertokens_python.recipe.thirdparty.api.implementation import \
    APIImplementation as ThirdPartyImplementation
from supertokens_python.recipe.thirdparty.interfaces import \
    APIOptions as ThirdPartyApiOptions
from supertokens_python.recipe.thirdparty.interfaces import (
    AuthorisationUrlGetResponse, SignInUpPostResponse)
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import \
    APIInterface

from .emailpassword_api_impementation import \
    get_interface_impl as get_ep_interface_impl
from .thirdparty_api_implementation import \
    get_interface_impl as get_tp_interface_impl


class APIImplementation(APIInterface):
    """APIImplementation.
    """

    def __init__(self):
        """__init__.
        """
        super().__init__()
        emailpassword_implementation = EmailPasswordImplementation()
        self.ep_email_exists_get = emailpassword_implementation.email_exists_get
        self.ep_generate_password_reset_token_post = emailpassword_implementation.generate_password_reset_token_post
        self.ep_password_reset_post = emailpassword_implementation.password_reset_post
        self.ep_sign_in_post = emailpassword_implementation.sign_in_post
        self.ep_sign_up_post = emailpassword_implementation.sign_up_post
        derived_ep = get_ep_interface_impl(self)
        emailpassword_implementation.email_exists_get = derived_ep.email_exists_get
        emailpassword_implementation.generate_password_reset_token_post = derived_ep.generate_password_reset_token_post
        emailpassword_implementation.password_reset_post = derived_ep.password_reset_post
        emailpassword_implementation.sign_in_post = derived_ep.sign_in_post
        emailpassword_implementation.sign_up_post = derived_ep.sign_up_post

        thirdparty_implementation = ThirdPartyImplementation()
        self.tp_authorisation_url_get = thirdparty_implementation.authorisation_url_get
        self.tp_sign_in_up_post = thirdparty_implementation.sign_in_up_post
        self.tp_apple_redirect_handler_post = thirdparty_implementation.apple_redirect_handler_post
        derived_tp = get_tp_interface_impl(self)
        thirdparty_implementation.authorisation_url_get = derived_tp.authorisation_url_get
        thirdparty_implementation.sign_in_up_post = derived_tp.sign_in_up_post
        thirdparty_implementation.apple_redirect_handler_post = derived_tp.apple_redirect_handler_post

    async def emailpassword_email_exists_get(self, email: str, api_options: EmailPasswordApiOptions, user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        """emailpassword_email_exists_get.

        Parameters
        ----------
        email : str
            email
        api_options : EmailPasswordApiOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        EmailExistsGetResponse

        """
        return await self.ep_email_exists_get(email, api_options, user_context)

    async def generate_password_reset_token_post(self, form_fields: List[FormField],
                                                 api_options: EmailPasswordApiOptions, user_context: Dict[str, Any]) -> GeneratePasswordResetTokenPostResponse:
        """generate_password_reset_token_post.

        Parameters
        ----------
        form_fields : List[FormField]
            form_fields
        api_options : EmailPasswordApiOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        GeneratePasswordResetTokenPostResponse

        """
        return await self.ep_generate_password_reset_token_post(form_fields, api_options, user_context)

    async def password_reset_post(self, form_fields: List[FormField], token: str,
                                  api_options: EmailPasswordApiOptions, user_context: Dict[str, Any]) -> PasswordResetPostResponse:
        """password_reset_post.

        Parameters
        ----------
        form_fields : List[FormField]
            form_fields
        token : str
            token
        api_options : EmailPasswordApiOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        PasswordResetPostResponse

        """
        return await self.ep_password_reset_post(form_fields, token, api_options, user_context)

    async def thirdparty_sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None], auth_code_response: Union[Dict[str, Any], None],
                                         api_options: ThirdPartyApiOptions, user_context: Dict[str, Any]) -> SignInUpPostResponse:
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
        api_options : ThirdPartyApiOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignInUpPostResponse

        """
        return await self.tp_sign_in_up_post(provider, code, redirect_uri, client_id, auth_code_response, api_options, user_context)

    async def emailpassword_sign_in_post(self, form_fields: List[FormField],
                                         api_options: EmailPasswordApiOptions, user_context: Dict[str, Any]) -> SignInPostResponse:
        """emailpassword_sign_in_post.

        Parameters
        ----------
        form_fields : List[FormField]
            form_fields
        api_options : EmailPasswordApiOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignInPostResponse

        """
        return await self.ep_sign_in_post(form_fields, api_options, user_context)

    async def emailpassword_sign_up_post(self, form_fields: List[FormField],
                                         api_options: EmailPasswordApiOptions, user_context: Dict[str, Any]) -> SignUpPostResponse:
        """emailpassword_sign_up_post.

        Parameters
        ----------
        form_fields : List[FormField]
            form_fields
        api_options : EmailPasswordApiOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignUpPostResponse

        """
        return await self.ep_sign_up_post(form_fields, api_options, user_context)

    async def authorisation_url_get(self, provider: Provider, api_options: ThirdPartyApiOptions, user_context: Dict[str, Any]) -> AuthorisationUrlGetResponse:
        """authorisation_url_get.

        Parameters
        ----------
        provider : Provider
            provider
        api_options : ThirdPartyApiOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        AuthorisationUrlGetResponse

        """
        return await self.tp_authorisation_url_get(provider, api_options, user_context)

    async def apple_redirect_handler_post(self, code: str, state: str, api_options: ThirdPartyApiOptions, user_context: Dict[str, Any]):
        """apple_redirect_handler_post.

        Parameters
        ----------
        code : str
            code
        state : str
            state
        api_options : ThirdPartyApiOptions
            api_options
        user_context : Dict[str, Any]
            user_context
        """
        return await self.tp_apple_redirect_handler_post(code, state, api_options, user_context)
