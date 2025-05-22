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

from typing import Any, Dict, Union

from supertokens_python.recipe.multifactorauth.asyncio import (
    assert_allowed_to_setup_factor_else_throw_invalid_claim_error,
)
from supertokens_python.recipe.multifactorauth.multi_factor_auth_claim import (
    MultiFactorAuthClaim,
)
from supertokens_python.recipe.multifactorauth.recipe import MultiFactorAuthRecipe
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.exceptions import UnauthorisedError  # noqa: E402
from supertokens_python.types.response import GeneralErrorResponse

from ..interfaces import APIInterface, APIOptions
from ..types import (
    CreateDeviceOkResult,
    DeviceAlreadyExistsError,
    InvalidTOTPError,
    LimitReachedError,
    ListDevicesOkResult,
    RemoveDeviceOkResult,
    UnknownDeviceError,
    UnknownUserIdError,
    VerifyDeviceOkResult,
    VerifyTOTPOkResult,
)


class APIImplementation(APIInterface):
    async def create_device_post(
        self,
        device_name: Union[str, None],
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[CreateDeviceOkResult, DeviceAlreadyExistsError, GeneralErrorResponse]:
        user_id = session.get_user_id()

        mfa_instance = MultiFactorAuthRecipe.get_instance()
        if mfa_instance is None:
            raise Exception("should never come here")

        await assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
            session, "totp", user_context
        )

        create_device_res = await options.recipe_implementation.create_device(
            user_id=user_id,
            user_identifier_info=None,
            device_name=device_name,
            skew=None,
            period=None,
            user_context=user_context,
        )

        if isinstance(create_device_res, UnknownUserIdError):
            raise UnauthorisedError("Session user not found")
        return create_device_res

    async def list_devices_get(
        self,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[ListDevicesOkResult, GeneralErrorResponse]:
        user_id = session.get_user_id()

        return await options.recipe_implementation.list_devices(
            user_id=user_id,
            user_context=user_context,
        )

    async def remove_device_post(
        self,
        device_name: str,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[RemoveDeviceOkResult, GeneralErrorResponse]:
        user_id = session.get_user_id()

        device_list = await options.recipe_implementation.list_devices(
            user_id=user_id, user_context=user_context
        )

        # MFA should be completed when trying to remove a verified TOTP device
        if any(
            [
                device.name == device_name and device.verified
                for device in device_list.devices
            ]
        ):
            await session.assert_claims(
                [
                    MultiFactorAuthClaim.validators.has_completed_mfa_requirements_for_auth()
                ]
            )

        return await options.recipe_implementation.remove_device(
            user_id=user_id,
            device_name=device_name,
            user_context=user_context,
        )

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
        user_id = session.get_user_id()
        tenant_id = session.get_tenant_id()

        mfa_instance = MultiFactorAuthRecipe.get_instance()
        if mfa_instance is None:
            raise Exception("should never come here")

        await assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
            session, "totp", user_context
        )

        res = await options.recipe_implementation.verify_device(
            tenant_id=tenant_id,
            user_id=user_id,
            device_name=device_name,
            totp=totp,
            user_context=user_context,
        )

        if isinstance(res, VerifyDeviceOkResult):
            await mfa_instance.recipe_implementation.mark_factor_as_complete_in_session(
                session=session,
                factor_id="totp",
                user_context=user_context,
            )

        return res

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
        user_id = session.get_user_id()
        tenant_id = session.get_tenant_id()

        mfa_instance = MultiFactorAuthRecipe.get_instance()
        if mfa_instance is None:
            raise Exception("should never come here")

        res = await options.recipe_implementation.verify_totp(
            tenant_id=tenant_id,
            user_id=user_id,
            totp=totp,
            user_context=user_context,
        )

        if isinstance(res, VerifyTOTPOkResult):
            await mfa_instance.recipe_implementation.mark_factor_as_complete_in_session(
                session=session,
                factor_id="totp",
                user_context=user_context,
            )

        return res
