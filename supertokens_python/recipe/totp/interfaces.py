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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

if TYPE_CHECKING:
    from supertokens_python import AppInfo
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.recipe.totp.recipe import TOTPRecipe
    from supertokens_python.types.response import GeneralErrorResponse

    from .types import (
        CreateDeviceOkResult,
        DeviceAlreadyExistsError,
        InvalidTOTPError,
        LimitReachedError,
        ListDevicesOkResult,
        RemoveDeviceOkResult,
        TOTPNormalisedConfig,
        UnknownDeviceError,
        UnknownUserIdError,
        UpdateDeviceOkResult,
        UserIdentifierInfoDoesNotExistError,
        UserIdentifierInfoOkResult,
        VerifyDeviceOkResult,
        VerifyTOTPOkResult,
    )


class RecipeInterface(ABC):
    @abstractmethod
    async def get_user_identifier_info_for_user_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[
        UserIdentifierInfoOkResult,
        UnknownUserIdError,
        UserIdentifierInfoDoesNotExistError,
    ]:
        pass

    @abstractmethod
    async def create_device(
        self,
        user_id: str,
        user_identifier_info: Optional[str],
        device_name: Optional[str],
        skew: Optional[int],
        period: Optional[int],
        user_context: Dict[str, Any],
    ) -> Union[
        CreateDeviceOkResult,
        DeviceAlreadyExistsError,
        UnknownUserIdError,
    ]:
        pass

    @abstractmethod
    async def update_device(
        self,
        user_id: str,
        existing_device_name: str,
        new_device_name: str,
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateDeviceOkResult,
        UnknownDeviceError,
        DeviceAlreadyExistsError,
    ]:
        pass

    @abstractmethod
    async def list_devices(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> ListDevicesOkResult:
        pass

    @abstractmethod
    async def remove_device(
        self, user_id: str, device_name: str, user_context: Dict[str, Any]
    ) -> RemoveDeviceOkResult:
        pass

    @abstractmethod
    async def verify_device(
        self,
        tenant_id: str,
        user_id: str,
        device_name: str,
        totp: str,
        user_context: Dict[str, Any],
    ) -> Union[
        VerifyDeviceOkResult,
        UnknownDeviceError,
        InvalidTOTPError,
        LimitReachedError,
    ]:
        pass

    @abstractmethod
    async def verify_totp(
        self, tenant_id: str, user_id: str, totp: str, user_context: Dict[str, Any]
    ) -> Union[
        VerifyTOTPOkResult,
        UnknownUserIdError,
        InvalidTOTPError,
        LimitReachedError,
    ]:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: TOTPNormalisedConfig,
        recipe_implementation: RecipeInterface,
        app_info: AppInfo,
        recipe_instance: TOTPRecipe,
    ):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config = config
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.app_info = app_info
        self.recipe_instance = recipe_instance


class APIInterface(ABC):
    def __init__(self):
        self.disable_create_device_post = False
        self.disable_list_devices_get = False
        self.disable_remove_device_post = False
        self.disable_verify_device_post = False
        self.disable_verify_totp_post = False

    @abstractmethod
    async def create_device_post(
        self,
        device_name: Union[str, None],
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[CreateDeviceOkResult, DeviceAlreadyExistsError, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def list_devices_get(
        self,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[ListDevicesOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def remove_device_post(
        self,
        device_name: str,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[RemoveDeviceOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def verify_device_post(
        self,
        device_name: str,
        totp: str,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[
        VerifyDeviceOkResult,
        UnknownDeviceError,
        InvalidTOTPError,
        LimitReachedError,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def verify_totp_post(
        self,
        totp: str,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[
        VerifyTOTPOkResult,
        UnknownUserIdError,
        InvalidTOTPError,
        LimitReachedError,
        GeneralErrorResponse,
    ]:
        pass
