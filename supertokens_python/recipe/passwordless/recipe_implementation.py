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

from supertokens_python.querier import Querier
from typing import TYPE_CHECKING, Union, List

from .types import DeviceType, User, DeviceCode

if TYPE_CHECKING:
    from .interfaces import CreateCodeResult, RevokeCodeResult, RevokeAllCodesResult, UpdateUserResult, \
        ConsumeCodeResult, CreateNewCodeForDeviceResult
from .interfaces import RecipeInterface, CreateNewCodeForDeviceOkResult, \
    CreateNewCodeForDeviceUserInputCodeAlreadyUsedErrorResult, CreateNewCodeForDeviceRestartFlowErrorResult, \
    CreateCodeOkResult, ConsumeCodeOkResult, ConsumeCodeRestartFlowErrorResult, \
    ConsumeCodeIncorrectUserInputCodeErrorResult, ConsumeCodeExpiredUserInputCodeErrorResult, \
    UpdateUserOkResult, UpdateUserUnknownUserIdErrorResult, UpdateUserEmailAlreadyExistsErrorResult, \
    UpdateUserPhoneNumberAlreadyExistsErrorResult, RevokeAllCodesOkResult, RevokeCodeOkResult
from supertokens_python.normalised_url_path import NormalisedURLPath


class RecipeImplementation(RecipeInterface):

    def __init__(self, querier: Querier):
        super().__init__()
        self.querier = querier

    async def create_code(self, email: Union[None, str] = None, phone_number: Union[None, str] = None,
                          user_input_code: Union[None, str] = None) -> CreateCodeResult:
        data = {}
        if user_input_code is not None:
            data = {
                **data,
                'userInputCode': user_input_code
            }
        if email is not None:
            data = {
                **data,
                'email': email
            }
        if phone_number is not None:
            data = {
                **data,
                'email': phone_number
            }
        result = await self.querier.send_post_request(NormalisedURLPath('/recipe/signinup/code'), data)
        return CreateCodeOkResult(
            pre_auth_session_id=result['preAuthSessionId'],
            code_id=result['codeId'],
            device_id=result['deviceId'],
            user_input_code=result['userInputCode'],
            link_code=result['linkCode'],
            time_created=result['timeCreated'],
            code_life_time=result['codeLifetime'],
        )

    async def create_new_code_for_device(self, device_id: str,
                                         user_input_code: Union[str, None] = None) -> CreateNewCodeForDeviceResult:
        data = {
            'deviceId': device_id
        }
        if user_input_code is not None:
            data = {
                **data,
                'userInputCode': user_input_code
            }
        result = await self.querier.send_post_request(NormalisedURLPath('/recipe/signinup/code'), data)
        if result['status'] == 'RESTART_FLOW_ERROR':
            return CreateNewCodeForDeviceRestartFlowErrorResult()
        elif result['status'] == 'USER_INPUT_CODE_ALREADY_USED_ERROR':
            return CreateNewCodeForDeviceUserInputCodeAlreadyUsedErrorResult()
        return CreateNewCodeForDeviceOkResult(
            pre_auth_session_id=result['preAuthSessionId'],
            code_id=result['codeId'],
            device_id=result['deviceId'],
            user_input_code=result['userInputCode'],
            link_code=result['linkCode'],
            code_life_time=result['codeLifetime'],
            time_created=result['timeCreated']
        )

    async def consume_code(self, pre_auth_session_id: str, user_input_code: Union[str, None] = None,
                           device_id: Union[str, None] = None, link_code: Union[str, None] = None) -> ConsumeCodeResult:
        data = {
            'preAuthSessionId': pre_auth_session_id
        }
        if device_id is not None:
            data = {
                **data,
                'deviceId': device_id,
                'userInputCode': user_input_code
            }
        else:
            data = {
                **data,
                'linkCode': link_code
            }
        result = await self.querier.send_post_request(NormalisedURLPath('/recipe/signinup/code/consume'), data)
        if result['status'] == 'OK':
            email = None
            phone_number = None
            if 'email' in result['user']:
                email = result['user']['email']
            if 'phoneNumber' in result['user']:
                phone_number = result['user']['phoneNumber']
            user = User(user_id=result['user']['id'],
                        email=email,
                        phone_number=phone_number,
                        time_joined=result['user']['timeJoined'])
            return ConsumeCodeOkResult(result['createdNewUser'], user)
        elif result['status'] == 'RESTART_FLOW_ERROR':
            return ConsumeCodeRestartFlowErrorResult()
        elif result['status'] == 'INCORRECT_USER_INPUT_CODE_ERROR':
            return ConsumeCodeIncorrectUserInputCodeErrorResult(
                failed_code_input_attempt_count=result['failedCodeInputAttemptCount'],
                maximum_code_input_attempts=result['maximumCodeInputAttempts']
            )
        return ConsumeCodeExpiredUserInputCodeErrorResult(
            failed_code_input_attempt_count=result['failedCodeInputAttemptCount'],
            maximum_code_input_attempts=result['maximumCodeInputAttempts']
        )

    async def get_user_by_id(self, user_id: str) -> Union[User, None]:
        param = {
            'userId': user_id
        }
        result = await self.querier.send_get_request(NormalisedURLPath('/recipe/user'), param)
        if result['status'] == 'OK':
            email = None
            phone_number = None
            if 'email' in result['user']:
                email = result['user']['email']
            if 'phoneNumber' in result['user']:
                phone_number = result['user']['phoneNumber']
            return User(user_id=result['user']['id'],
                        email=email,
                        phone_number=phone_number,
                        time_joined=result['user']['timeJoined'])
        return None

    async def get_user_by_email(self, email: str) -> Union[User, None]:
        param = {
            'email': email
        }
        result = await self.querier.send_get_request(NormalisedURLPath('/recipe/user'), param)
        if result['status'] == 'OK':
            email = None
            phone_number = None
            if 'email' in result['user']:
                email = result['user']['email']
            if 'phoneNumber' in result['user']:
                phone_number = result['user']['phoneNumber']
            return User(user_id=result['user']['id'],
                        email=email,
                        phone_number=phone_number,
                        time_joined=result['user']['timeJoined'])
        return None

    async def get_user_by_phone_number(self, phone_number: str) -> Union[User, None]:
        param = {
            'phoneNumber': phone_number
        }
        result = await self.querier.send_get_request(NormalisedURLPath('/recipe/user'), param)
        if result['status'] == 'OK':
            email = None
            phone_number = None
            if 'email' in result['user']:
                email = result['user']['email']
            if 'phoneNumber' in result['user']:
                phone_number = result['user']['phoneNumber']
            return User(user_id=result['user']['id'],
                        email=email,
                        phone_number=phone_number,
                        time_joined=result['user']['timeJoined'])
        return None

    async def update_user(self, user_id: str, email: Union[str, None] = None,
                          phone_number: Union[str, None] = None) -> UpdateUserResult:
        data = {
            'userId': user_id
        }
        if email is not None:
            data = {
                **data,
                'email': email
            }
        if phone_number is not None:
            data = {
                **data,
                'phoneNumber': phone_number
            }
        result = await self.querier.send_put_request(NormalisedURLPath('/recipe/user'), data)
        if result['status'] == 'OK':
            return UpdateUserOkResult()
        elif result['status'] == 'UNKNOWN_USER_ID_ERROR':
            return UpdateUserUnknownUserIdErrorResult()
        elif result['status'] == 'EMAIL_ALREADY_EXISTS_ERROR':
            return UpdateUserEmailAlreadyExistsErrorResult()
        return UpdateUserPhoneNumberAlreadyExistsErrorResult()

    async def revoke_all_codes(self, email: Union[str, None] = None,
                               phone_number: Union[str, None] = None) -> RevokeAllCodesResult:
        data = {}
        if email is not None:
            data = {
                **data,
                'email': email
            }
        if phone_number is not None:
            data = {
                **data,
                'email': phone_number
            }
        await self.querier.send_post_request(NormalisedURLPath('/recipe/signinup/codes/remove'), data)
        return RevokeAllCodesOkResult()

    async def revoke_code(self, code_id: str) -> RevokeCodeResult:
        data = {
            'codeId': code_id
        }
        await self.querier.send_post_request(NormalisedURLPath('/recipe/signinup/code/remove'), data)
        return RevokeCodeOkResult()

    async def list_codes_by_email(self, email: str) -> List[DeviceType]:
        param = {
            'email': email
        }
        result = await self.querier.send_get_request(NormalisedURLPath('/recipe/signinup/codes'), param)
        devices = []
        if 'devices' in result:
            for device in result['devices']:
                codes = []
                if 'code' in device:
                    for code in device:
                        codes.append(DeviceCode(
                            code_id=code['codeId'],
                            time_created=code['timeCreated'],
                            code_life_time=code['codeLifetime']
                        ))
                email = None
                phone_number = None
                if 'email' in device:
                    email = device['email']
                if 'phoneNumber' in device:
                    phone_number = device['phoneNumber']
                devices.append(DeviceType(
                    pre_auth_session_id=device['preAuthSessionId'],
                    failed_code_input_attempt_count=device['failedCodeInputAttemptCount'],
                    codes=codes,
                    email=email,
                    phone_number=phone_number
                ))
        return devices

    async def list_codes_by_phone_number(self, phone_number: str) -> List[DeviceType]:
        param = {
            'phoneNumber': phone_number
        }
        result = await self.querier.send_get_request(NormalisedURLPath('/recipe/signinup/codes'), param)
        devices = []
        if 'devices' in result:
            for device in result['devices']:
                codes = []
                if 'code' in device:
                    for code in device:
                        codes.append(DeviceCode(
                            code_id=code['codeId'],
                            time_created=code['timeCreated'],
                            code_life_time=code['codeLifetime']
                        ))
                email = None
                phone_number = None
                if 'email' in device:
                    email = device['email']
                if 'phoneNumber' in device:
                    phone_number = device['phoneNumber']
                devices.append(DeviceType(
                    pre_auth_session_id=device['preAuthSessionId'],
                    failed_code_input_attempt_count=device['failedCodeInputAttemptCount'],
                    codes=codes,
                    email=email,
                    phone_number=phone_number
                ))
        return devices

    async def list_codes_by_device_id(self, device_id: str) -> Union[DeviceType, None]:
        param = {
            'deviceId': device_id
        }
        result = await self.querier.send_get_request(NormalisedURLPath('/recipe/signinup/codes'), param)
        if 'devices' in result and len(result['devices']) == 1:
            codes = []
            if 'code' in result['devices'][0]:
                for code in result['devices'][0]:
                    codes.append(DeviceCode(
                        code_id=code['codeId'],
                        time_created=code['timeCreated'],
                        code_life_time=code['codeLifetime']
                    ))
            email = None
            phone_number = None
            if 'email' in result['devices'][0]:
                email = result['devices'][0]['email']
            if 'phoneNumber' in result['devices'][0]:
                phone_number = result['devices'][0]['phoneNumber']
            return DeviceType(
                pre_auth_session_id=result['devices'][0]['preAuthSessionId'],
                failed_code_input_attempt_count=result['devices'][0]['failedCodeInputAttemptCount'],
                codes=codes,
                email=email,
                phone_number=phone_number
            )
        return None

    async def list_codes_by_pre_auth_session_id(self, pre_auth_session_id: str) -> Union[DeviceType, None]:
        param = {
            'preAuthSessionId': pre_auth_session_id
        }
        result = await self.querier.send_get_request(NormalisedURLPath('/recipe/signinup/codes'), param)
        if 'devices' in result and len(result['devices']) == 1:
            codes = []
            if 'code' in result['devices'][0]:
                for code in result['devices'][0]:
                    codes.append(DeviceCode(
                        code_id=code['codeId'],
                        time_created=code['timeCreated'],
                        code_life_time=code['codeLifetime']
                    ))
            email = None
            phone_number = None
            if 'email' in result['devices'][0]:
                email = result['devices'][0]['email']
            if 'phoneNumber' in result['devices'][0]:
                phone_number = result['devices'][0]['phoneNumber']
            return DeviceType(
                pre_auth_session_id=result['devices'][0]['preAuthSessionId'],
                failed_code_input_attempt_count=result['devices'][0]['failedCodeInputAttemptCount'],
                codes=codes,
                email=email,
                phone_number=phone_number
            )
        return None
