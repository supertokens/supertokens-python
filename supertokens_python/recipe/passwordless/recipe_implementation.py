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

from supertokens_python.querier import Querier

from .types import DeviceCode, DeviceType, User

from supertokens_python.normalised_url_path import NormalisedURLPath

from .interfaces import (
    ConsumeCodeExpiredUserInputCodeError,
    ConsumeCodeIncorrectUserInputCodeError,
    ConsumeCodeOkResult,
    ConsumeCodeRestartFlowError,
    CreateCodeOkResult,
    CreateNewCodeForDeviceOkResult,
    CreateNewCodeForDeviceRestartFlowError,
    CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
    DeleteUserInfoOkResult,
    DeleteUserInfoUnknownUserIdError,
    RecipeInterface,
    RevokeAllCodesOkResult,
    RevokeCodeOkResult,
    UpdateUserEmailAlreadyExistsError,
    UpdateUserOkResult,
    UpdateUserPhoneNumberAlreadyExistsError,
    UpdateUserUnknownUserIdError,
)


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def create_code(
        self,
        email: Union[None, str],
        phone_number: Union[None, str],
        user_input_code: Union[None, str],
        user_context: Dict[str, Any],
    ) -> CreateCodeOkResult:
        data: Dict[str, Any] = {}
        if user_input_code is not None:
            data = {**data, "userInputCode": user_input_code}
        if email is not None:
            data = {**data, "email": email}
        if phone_number is not None:
            data = {**data, "phoneNumber": phone_number}
        result = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/signinup/code"), data
        )
        return CreateCodeOkResult(
            pre_auth_session_id=result["preAuthSessionId"],
            code_id=result["codeId"],
            device_id=result["deviceId"],
            user_input_code=result["userInputCode"],
            link_code=result["linkCode"],
            time_created=result["timeCreated"],
            code_life_time=result["codeLifetime"],
        )

    async def create_new_code_for_device(
        self,
        device_id: str,
        user_input_code: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        CreateNewCodeForDeviceOkResult,
        CreateNewCodeForDeviceRestartFlowError,
        CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
    ]:
        data = {"deviceId": device_id}
        if user_input_code is not None:
            data = {**data, "userInputCode": user_input_code}
        result = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/signinup/code"), data
        )
        if result["status"] == "RESTART_FLOW_ERROR":
            return CreateNewCodeForDeviceRestartFlowError()
        if result["status"] == "USER_INPUT_CODE_ALREADY_USED_ERROR":
            return CreateNewCodeForDeviceUserInputCodeAlreadyUsedError()
        return CreateNewCodeForDeviceOkResult(
            pre_auth_session_id=result["preAuthSessionId"],
            code_id=result["codeId"],
            device_id=result["deviceId"],
            user_input_code=result["userInputCode"],
            link_code=result["linkCode"],
            code_life_time=result["codeLifetime"],
            time_created=result["timeCreated"],
        )

    async def consume_code(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        ConsumeCodeOkResult,
        ConsumeCodeIncorrectUserInputCodeError,
        ConsumeCodeExpiredUserInputCodeError,
        ConsumeCodeRestartFlowError,
    ]:
        data = {"preAuthSessionId": pre_auth_session_id}
        if device_id is not None:
            data = {**data, "deviceId": device_id, "userInputCode": user_input_code}
        else:
            data = {**data, "linkCode": link_code}
        result = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/signinup/code/consume"), data
        )
        if result["status"] == "OK":
            email = None
            phone_number = None
            if "email" in result["user"]:
                email = result["user"]["email"]
            if "phoneNumber" in result["user"]:
                phone_number = result["user"]["phoneNumber"]
            user = User(
                user_id=result["user"]["id"],
                email=email,
                phone_number=phone_number,
                time_joined=result["user"]["timeJoined"],
            )
            return ConsumeCodeOkResult(result["createdNewUser"], user)
        if result["status"] == "RESTART_FLOW_ERROR":
            return ConsumeCodeRestartFlowError()
        if result["status"] == "INCORRECT_USER_INPUT_CODE_ERROR":
            return ConsumeCodeIncorrectUserInputCodeError(
                failed_code_input_attempt_count=result["failedCodeInputAttemptCount"],
                maximum_code_input_attempts=result["maximumCodeInputAttempts"],
            )
        return ConsumeCodeExpiredUserInputCodeError(
            failed_code_input_attempt_count=result["failedCodeInputAttemptCount"],
            maximum_code_input_attempts=result["maximumCodeInputAttempts"],
        )

    async def get_user_by_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        param = {"userId": user_id}
        result = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/user"), param
        )
        if result["status"] == "OK":
            email = None
            phone_number = None
            if "email" in result["user"]:
                email = result["user"]["email"]
            if "phoneNumber" in result["user"]:
                phone_number = result["user"]["phoneNumber"]
            return User(
                user_id=result["user"]["id"],
                email=email,
                phone_number=phone_number,
                time_joined=result["user"]["timeJoined"],
            )
        return None

    async def get_user_by_email(
        self, email: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        param = {"email": email}
        result = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/user"), param
        )
        if result["status"] == "OK":
            email_resp = None
            phone_number_resp = None
            if "email" in result["user"]:
                email_resp = result["user"]["email"]
            if "phoneNumber" in result["user"]:
                phone_number_resp = result["user"]["phoneNumber"]
            return User(
                user_id=result["user"]["id"],
                email=email_resp,
                phone_number=phone_number_resp,
                time_joined=result["user"]["timeJoined"],
            )
        return None

    async def get_user_by_phone_number(
        self, phone_number: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        param = {"phoneNumber": phone_number}
        result = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/user"), param
        )
        if result["status"] == "OK":
            email_resp = None
            phone_number_resp = None
            if "email" in result["user"]:
                email_resp = result["user"]["email"]
            if "phoneNumber" in result["user"]:
                phone_number_resp = result["user"]["phoneNumber"]
            return User(
                user_id=result["user"]["id"],
                email=email_resp,
                phone_number=phone_number_resp,
                time_joined=result["user"]["timeJoined"],
            )
        return None

    async def update_user(
        self,
        user_id: str,
        email: Union[str, None],
        phone_number: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateUserOkResult,
        UpdateUserUnknownUserIdError,
        UpdateUserEmailAlreadyExistsError,
        UpdateUserPhoneNumberAlreadyExistsError,
    ]:
        data = {"userId": user_id}
        if email is not None:
            data = {**data, "email": email}
        if phone_number is not None:
            data = {**data, "phoneNumber": phone_number}
        result = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/user"), data
        )
        if result["status"] == "OK":
            return UpdateUserOkResult()
        if result["status"] == "UNKNOWN_USER_ID_ERROR":
            return UpdateUserUnknownUserIdError()
        if result["status"] == "EMAIL_ALREADY_EXISTS_ERROR":
            return UpdateUserEmailAlreadyExistsError()
        return UpdateUserPhoneNumberAlreadyExistsError()

    async def delete_email_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
        data = {"userId": user_id, "email": None}
        result = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/user"), data
        )
        if result["status"] == "OK":
            return DeleteUserInfoOkResult()
        if result.get("EMAIL_ALREADY_EXISTS_ERROR"):
            raise Exception("Should never come here")
        if result.get("PHONE_NUMBER_ALREADY_EXISTS_ERROR"):
            raise Exception("Should never come here")
        return DeleteUserInfoUnknownUserIdError()

    async def delete_phone_number_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[DeleteUserInfoOkResult, DeleteUserInfoUnknownUserIdError]:
        data = {"userId": user_id, "phoneNumber": None}
        result = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/user"), data
        )
        if result["status"] == "OK":
            return DeleteUserInfoOkResult()
        if result.get("EMAIL_ALREADY_EXISTS_ERROR"):
            raise Exception("Should never come here")
        if result.get("PHONE_NUMBER_ALREADY_EXISTS_ERROR"):
            raise Exception("Should never come here")
        return DeleteUserInfoUnknownUserIdError()

    async def revoke_all_codes(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        user_context: Dict[str, Any],
    ) -> RevokeAllCodesOkResult:
        data: Dict[str, Any] = {}
        if email is not None:
            data = {**data, "email": email}
        if phone_number is not None:
            data = {**data, "email": phone_number}
        await self.querier.send_post_request(
            NormalisedURLPath("/recipe/signinup/codes/remove"), data
        )
        return RevokeAllCodesOkResult()

    async def revoke_code(
        self, code_id: str, user_context: Dict[str, Any]
    ) -> RevokeCodeOkResult:
        data = {"codeId": code_id}
        await self.querier.send_post_request(
            NormalisedURLPath("/recipe/signinup/code/remove"), data
        )
        return RevokeCodeOkResult()

    async def list_codes_by_email(
        self, email: str, user_context: Dict[str, Any]
    ) -> List[DeviceType]:
        param = {"email": email}
        result = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/signinup/codes"), param
        )
        devices: List[DeviceType] = []
        if "devices" in result:
            for device in result["devices"]:
                codes: List[DeviceCode] = []
                if "code" in device:
                    for code in device:
                        codes.append(
                            DeviceCode(
                                code_id=code["codeId"],
                                time_created=code["timeCreated"],
                                code_life_time=code["codeLifetime"],
                            )
                        )
                email_resp = None
                phone_number_resp = None
                if "email" in device:
                    email_resp = device["email"]
                if "phoneNumber" in device:
                    phone_number_resp = device["phoneNumber"]
                devices.append(
                    DeviceType(
                        pre_auth_session_id=device["preAuthSessionId"],
                        failed_code_input_attempt_count=device[
                            "failedCodeInputAttemptCount"
                        ],
                        codes=codes,
                        email=email_resp,
                        phone_number=phone_number_resp,
                    )
                )
        return devices

    async def list_codes_by_phone_number(
        self, phone_number: str, user_context: Dict[str, Any]
    ) -> List[DeviceType]:
        param = {"phoneNumber": phone_number}
        result = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/signinup/codes"), param
        )
        devices: List[DeviceType] = []
        if "devices" in result:
            for device in result["devices"]:
                codes: List[DeviceCode] = []
                if "code" in device:
                    for code in device:
                        codes.append(
                            DeviceCode(
                                code_id=code["codeId"],
                                time_created=code["timeCreated"],
                                code_life_time=code["codeLifetime"],
                            )
                        )
                email_resp = None
                phone_number_resp = None
                if "email" in device:
                    email_resp = device["email"]
                if "phoneNumber" in device:
                    phone_number_resp = device["phoneNumber"]
                devices.append(
                    DeviceType(
                        pre_auth_session_id=device["preAuthSessionId"],
                        failed_code_input_attempt_count=device[
                            "failedCodeInputAttemptCount"
                        ],
                        codes=codes,
                        email=email_resp,
                        phone_number=phone_number_resp,
                    )
                )
        return devices

    async def list_codes_by_device_id(
        self, device_id: str, user_context: Dict[str, Any]
    ) -> Union[DeviceType, None]:
        param = {"deviceId": device_id}
        result = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/signinup/codes"), param
        )
        if "devices" in result and len(result["devices"]) == 1:
            codes: List[DeviceCode] = []
            if "code" in result["devices"][0]:
                for code in result["devices"][0]:
                    codes.append(
                        DeviceCode(
                            code_id=code["codeId"],
                            time_created=code["timeCreated"],
                            code_life_time=code["codeLifetime"],
                        )
                    )
            email = None
            phone_number = None
            if "email" in result["devices"][0]:
                email = result["devices"][0]["email"]
            if "phoneNumber" in result["devices"][0]:
                phone_number = result["devices"][0]["phoneNumber"]
            return DeviceType(
                pre_auth_session_id=result["devices"][0]["preAuthSessionId"],
                failed_code_input_attempt_count=result["devices"][0][
                    "failedCodeInputAttemptCount"
                ],
                codes=codes,
                email=email,
                phone_number=phone_number,
            )
        return None

    async def list_codes_by_pre_auth_session_id(
        self, pre_auth_session_id: str, user_context: Dict[str, Any]
    ) -> Union[DeviceType, None]:
        param = {"preAuthSessionId": pre_auth_session_id}
        result = await self.querier.send_get_request(
            NormalisedURLPath("/recipe/signinup/codes"), param
        )
        if "devices" in result and len(result["devices"]) == 1:
            codes: List[DeviceCode] = []
            if "code" in result["devices"][0]:
                for code in result["devices"][0]:
                    codes.append(
                        DeviceCode(
                            code_id=code["codeId"],
                            time_created=code["timeCreated"],
                            code_life_time=code["codeLifetime"],
                        )
                    )
            email = None
            phone_number = None
            if "email" in result["devices"][0]:
                email = result["devices"][0]["email"]
            if "phoneNumber" in result["devices"][0]:
                phone_number = result["devices"][0]["phoneNumber"]
            return DeviceType(
                pre_auth_session_id=result["devices"][0]["preAuthSessionId"],
                failed_code_input_attempt_count=result["devices"][0][
                    "failedCodeInputAttemptCount"
                ],
                codes=codes,
                email=email,
                phone_number=phone_number,
            )
        return None
