# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from supertokens_python.types.recipe import BaseAPIInterface, BaseRecipeInterface

from .types import (
    CreateLoginRequestInvalidClientError,
    CreateLoginRequestOkResult,
    CreateOrUpdateClientDuplicateIdpEntityError,
    CreateOrUpdateClientInvalidMetadataXMLError,
    CreateOrUpdateClientOkResult,
    GetUserInfoInvalidTokenError,
    GetUserInfoOkResult,
    ListClientsOkResult,
    RemoveClientOkResult,
    VerifySAMLResponseIDPLoginDisallowedError,
    VerifySAMLResponseInvalidClientError,
    VerifySAMLResponseInvalidRelayStateError,
    VerifySAMLResponseOkResult,
    VerifySAMLResponseVerificationFailedError,
)

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.supertokens import AppInfo

    from .utils import NormalisedSAMLConfig


class APIOptions:
    def __init__(
        self,
        app_info: AppInfo,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: NormalisedSAMLConfig,
        recipe_implementation: RecipeInterface,
    ):
        self.app_info = app_info
        self.request = request
        self.response = response
        self.recipe_id = recipe_id
        self.config = config
        self.recipe_implementation = recipe_implementation


class RecipeInterface(BaseRecipeInterface):
    @abstractmethod
    async def create_or_update_client(
        self,
        tenant_id: str,
        redirect_uris: List[str],
        default_redirect_uri: str,
        metadata_xml: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        allow_idp_initiated_login: Optional[bool],
        enable_request_signing: Optional[bool],
        user_context: Dict[str, Any],
    ) -> Union[
        CreateOrUpdateClientOkResult,
        CreateOrUpdateClientInvalidMetadataXMLError,
        CreateOrUpdateClientDuplicateIdpEntityError,
    ]: ...

    @abstractmethod
    async def list_clients(
        self,
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> ListClientsOkResult: ...

    @abstractmethod
    async def remove_client(
        self,
        tenant_id: str,
        client_id: str,
        user_context: Dict[str, Any],
    ) -> RemoveClientOkResult: ...

    @abstractmethod
    async def create_login_request(
        self,
        tenant_id: str,
        client_id: str,
        redirect_uri: str,
        acs_url: str,
        state: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[
        CreateLoginRequestOkResult,
        CreateLoginRequestInvalidClientError,
    ]: ...

    @abstractmethod
    async def verify_saml_response(
        self,
        tenant_id: str,
        saml_response: str,
        relay_state: Optional[str],
        user_context: Dict[str, Any],
    ) -> Union[
        VerifySAMLResponseOkResult,
        VerifySAMLResponseVerificationFailedError,
        VerifySAMLResponseInvalidRelayStateError,
        VerifySAMLResponseInvalidClientError,
        VerifySAMLResponseIDPLoginDisallowedError,
    ]: ...

    @abstractmethod
    async def get_user_info(
        self,
        tenant_id: str,
        access_token: str,
        client_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        GetUserInfoOkResult,
        GetUserInfoInvalidTokenError,
    ]: ...


class APIInterface(BaseAPIInterface):
    disable_login_get: bool = False
    disable_callback_post: bool = False

    @abstractmethod
    async def login_get(
        self,
        tenant_id: str,
        client_id: str,
        redirect_uri: str,
        state: Optional[str],
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        CreateLoginRequestOkResult,
        CreateLoginRequestInvalidClientError,
    ]: ...

    @abstractmethod
    async def callback_post(
        self,
        tenant_id: str,
        saml_response: str,
        relay_state: Optional[str],
        options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        VerifySAMLResponseOkResult,
        VerifySAMLResponseVerificationFailedError,
        VerifySAMLResponseInvalidRelayStateError,
        VerifySAMLResponseInvalidClientError,
        VerifySAMLResponseIDPLoginDisallowedError,
    ]: ...
