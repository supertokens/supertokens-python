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

from typing import Any, Dict, List, Optional, Union

from supertokens_python.asyncio import get_user
from supertokens_python.auth_utils import (
    link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info,
)
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.emailverification.recipe import EmailVerificationRecipe
from supertokens_python.recipe.passwordless.interfaces import (
    CheckCodeExpiredUserInputCodeError,
    CheckCodeIncorrectUserInputCodeError,
    CheckCodeOkResult,
    CheckCodeRestartFlowError,
    ConsumeCodeExpiredUserInputCodeError,
    ConsumeCodeIncorrectUserInputCodeError,
    ConsumeCodeOkResult,
    ConsumeCodeRestartFlowError,
    ConsumedDevice,
    CreateCodeOkResult,
    CreateNewCodeForDeviceOkResult,
    CreateNewCodeForDeviceRestartFlowError,
    CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
    EmailChangeNotAllowedError,
    PhoneNumberChangeNotAllowedError,
    RecipeInterface,
    RevokeAllCodesOkResult,
    RevokeCodeOkResult,
    UpdateUserEmailAlreadyExistsError,
    UpdateUserOkResult,
    UpdateUserPhoneNumberAlreadyExistsError,
    UpdateUserUnknownUserIdError,
)
from supertokens_python.recipe.passwordless.types import DeviceCode, DeviceType
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError
from supertokens_python.utils import log_debug_message


class RecipeImplementation(RecipeInterface):
    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def consume_code(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        ConsumeCodeOkResult,
        ConsumeCodeIncorrectUserInputCodeError,
        ConsumeCodeExpiredUserInputCodeError,
        ConsumeCodeRestartFlowError,
        LinkingToSessionUserFailedError,
    ]:
        input_dict = {
            "preAuthSessionId": pre_auth_session_id,
        }
        if link_code is not None:
            input_dict["linkCode"] = link_code
        else:
            if user_input_code is None or device_id is None:
                return ConsumeCodeRestartFlowError()
            input_dict["userInputCode"] = user_input_code
            input_dict["deviceId"] = device_id

        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup/code/consume"),
            input_dict,
            user_context=user_context,
        )

        if response["status"] == "INCORRECT_USER_INPUT_CODE_ERROR":
            return ConsumeCodeIncorrectUserInputCodeError(
                failed_code_input_attempt_count=response["failedCodeInputAttemptCount"],
                maximum_code_input_attempts=response["maximumCodeInputAttempts"],
            )
        elif response["status"] == "EXPIRED_USER_INPUT_CODE_ERROR":
            return ConsumeCodeExpiredUserInputCodeError(
                failed_code_input_attempt_count=response["failedCodeInputAttemptCount"],
                maximum_code_input_attempts=response["maximumCodeInputAttempts"],
            )
        elif response["status"] == "RESTART_FLOW_ERROR":
            return ConsumeCodeRestartFlowError()

        # status == "OK"

        log_debug_message("Passwordless.consumeCode code consumed OK")

        recipe_user_id = RecipeUserId(response["recipeUserId"])

        updated_user = User.from_json(response["user"])

        link_result = await link_to_session_if_provided_else_create_primary_user_id_or_link_by_account_info(
            tenant_id=tenant_id,
            input_user=updated_user,
            recipe_user_id=recipe_user_id,
            session=session,
            user_context=user_context,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if isinstance(link_result, LinkingToSessionUserFailedError):
            return link_result

        updated_user = link_result.user

        response["user"] = updated_user

        return ConsumeCodeOkResult(
            user=updated_user,
            recipe_user_id=recipe_user_id,
            consumed_device=ConsumedDevice.from_json(response["consumedDevice"]),
            created_new_recipe_user=response["createdNewUser"],
        )

    async def check_code(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> Union[
        CheckCodeOkResult,
        CheckCodeIncorrectUserInputCodeError,
        CheckCodeExpiredUserInputCodeError,
        CheckCodeRestartFlowError,
    ]:
        input_dict = {
            "preAuthSessionId": pre_auth_session_id,
        }
        if link_code is not None:
            input_dict["linkCode"] = link_code
        else:
            if user_input_code is None or device_id is None:
                return CheckCodeRestartFlowError()
            input_dict["userInputCode"] = user_input_code
            input_dict["deviceId"] = device_id

        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup/code/check"),
            input_dict,
            user_context=user_context,
        )

        if response["status"] == "INCORRECT_USER_INPUT_CODE_ERROR":
            return CheckCodeIncorrectUserInputCodeError(
                failed_code_input_attempt_count=response["failedCodeInputAttemptCount"],
                maximum_code_input_attempts=response["maximumCodeInputAttempts"],
            )
        elif response["status"] == "EXPIRED_USER_INPUT_CODE_ERROR":
            return CheckCodeExpiredUserInputCodeError(
                failed_code_input_attempt_count=response["failedCodeInputAttemptCount"],
                maximum_code_input_attempts=response["maximumCodeInputAttempts"],
            )
        elif response["status"] == "RESTART_FLOW_ERROR":
            return CheckCodeRestartFlowError()

        # status == "OK"
        log_debug_message("Passwordless.checkCode code verified")

        return CheckCodeOkResult(
            consumed_device=ConsumedDevice.from_json(response["consumedDevice"])
        )

    async def create_code(
        self,
        email: Union[None, str],
        phone_number: Union[None, str],
        user_input_code: Union[None, str],
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> CreateCodeOkResult:
        input_dict: Dict[str, Any] = {}
        if email:
            input_dict["email"] = email
        if phone_number:
            input_dict["phoneNumber"] = phone_number
        if user_input_code:
            input_dict["userInputCode"] = user_input_code

        response = await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup/code"),
            input_dict,
            user_context=user_context,
        )
        return CreateCodeOkResult(
            pre_auth_session_id=response["preAuthSessionId"],
            code_id=response["codeId"],
            device_id=response["deviceId"],
            user_input_code=response["userInputCode"],
            link_code=response["linkCode"],
            code_life_time=response["codeLifetime"],
            time_created=response["timeCreated"],
        )

    async def create_new_code_for_device(
        self,
        device_id: str,
        user_input_code: Union[str, None],
        tenant_id: str,
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
            NormalisedURLPath(f"{tenant_id}/recipe/signinup/code"),
            data,
            user_context=user_context,
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

    async def list_codes_by_device_id(
        self, device_id: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[DeviceType, None]:
        param = {"deviceId": device_id}
        result = await self.querier.send_get_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup/codes"),
            param,
            user_context=user_context,
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

    async def list_codes_by_email(
        self, email: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> List[DeviceType]:
        param = {"email": email}
        result = await self.querier.send_get_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup/codes"),
            param,
            user_context=user_context,
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
        self, phone_number: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> List[DeviceType]:
        param = {"phoneNumber": phone_number}
        result = await self.querier.send_get_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup/codes"),
            param,
            user_context=user_context,
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

    async def list_codes_by_pre_auth_session_id(
        self, pre_auth_session_id: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> Union[DeviceType, None]:
        param = {"preAuthSessionId": pre_auth_session_id}
        result = await self.querier.send_get_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup/codes"),
            param,
            user_context=user_context,
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

    async def revoke_all_codes(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> RevokeAllCodesOkResult:
        data: Dict[str, Any] = {}
        if email is not None:
            data = {**data, "email": email}
        if phone_number is not None:
            data = {**data, "email": phone_number}
        await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup/codes/remove"),
            data,
            user_context=user_context,
        )
        return RevokeAllCodesOkResult()

    async def revoke_code(
        self, code_id: str, tenant_id: str, user_context: Dict[str, Any]
    ) -> RevokeCodeOkResult:
        data = {"codeId": code_id}
        await self.querier.send_post_request(
            NormalisedURLPath(f"{tenant_id}/recipe/signinup/code/remove"),
            data,
            user_context=user_context,
        )
        return RevokeCodeOkResult()

    async def delete_email_for_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> Union[UpdateUserOkResult, UpdateUserUnknownUserIdError]:
        data = {"recipeUserId": recipe_user_id.get_as_string(), "email": None}
        result = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/user"),
            data,
            None,
            user_context=user_context,
        )
        if result["status"] == "OK":
            return UpdateUserOkResult()
        return UpdateUserUnknownUserIdError()

    async def delete_phone_number_for_user(
        self, recipe_user_id: RecipeUserId, user_context: Dict[str, Any]
    ) -> Union[UpdateUserOkResult, UpdateUserUnknownUserIdError]:
        data = {"recipeUserId": recipe_user_id.get_as_string(), "phoneNumber": None}
        result = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/user"),
            data,
            None,
            user_context=user_context,
        )
        if result["status"] == "OK":
            return UpdateUserOkResult()
        return UpdateUserUnknownUserIdError()

    async def update_user(
        self,
        recipe_user_id: RecipeUserId,
        email: Union[str, None],
        phone_number: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateUserOkResult,
        UpdateUserUnknownUserIdError,
        UpdateUserEmailAlreadyExistsError,
        UpdateUserPhoneNumberAlreadyExistsError,
        EmailChangeNotAllowedError,
        PhoneNumberChangeNotAllowedError,
    ]:
        account_linking = AccountLinkingRecipe.get_instance()
        if email:
            user = await get_user(recipe_user_id.get_as_string(), user_context)
            if user is None:
                return UpdateUserUnknownUserIdError()

            ev_instance = EmailVerificationRecipe.get_instance_optional()
            is_email_verified = False
            if ev_instance:
                is_email_verified = (
                    await ev_instance.recipe_implementation.is_email_verified(
                        recipe_user_id=recipe_user_id,
                        email=email,
                        user_context=user_context,
                    )
                )

            is_email_change_allowed = await account_linking.is_email_change_allowed(
                user=user,
                is_verified=is_email_verified,
                new_email=email,
                session=None,
                user_context=user_context,
            )
            if not is_email_change_allowed.allowed:
                return EmailChangeNotAllowedError(
                    reason=(
                        "New email cannot be applied to existing account because of account takeover risks."
                        if is_email_change_allowed.reason == "ACCOUNT_TAKEOVER_RISK"
                        else "New email cannot be applied to existing account because there is another primary user with the same email address."
                    ),
                )

        input_dict = {
            "recipeUserId": recipe_user_id.get_as_string(),
        }
        if email:
            input_dict = {**input_dict, "email": email}
        if phone_number:
            input_dict = {**input_dict, "phoneNumber": phone_number}

        response = await self.querier.send_put_request(
            NormalisedURLPath("/recipe/user"),
            input_dict,
            None,
            user_context=user_context,
        )
        if response["status"] == "UNKNOWN_USER_ID_ERROR":
            return UpdateUserUnknownUserIdError()
        elif response["status"] == "EMAIL_ALREADY_EXISTS_ERROR":
            return UpdateUserEmailAlreadyExistsError()
        elif response["status"] == "PHONE_NUMBER_ALREADY_EXISTS_ERROR":
            return UpdateUserPhoneNumberAlreadyExistsError()
        elif response["status"] == "EMAIL_CHANGE_NOT_ALLOWED_ERROR":
            return EmailChangeNotAllowedError(
                reason=response["reason"],
            )
        elif response["status"] == "PHONE_NUMBER_CHANGE_NOT_ALLOWED_ERROR":
            return PhoneNumberChangeNotAllowedError(
                reason=response["reason"],
            )

        # status is OK
        user = await get_user(recipe_user_id.get_as_string(), user_context)
        if user is None:
            return UpdateUserUnknownUserIdError()

        await account_linking.verify_email_for_recipe_user_if_linked_accounts_are_verified(
            user=user,
            recipe_user_id=recipe_user_id,
            user_context=user_context,
        )
        return UpdateUserOkResult()
