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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Union

from supertokens_python.types import User

from ...types import APIResponse

if TYPE_CHECKING:
    from ...supertokens import AppInfo
    from .utils import DashboardConfig, UserWithMetadata

    from supertokens_python.recipe.session.interfaces import SessionInformationResult
    from supertokens_python.framework import BaseRequest, BaseResponse

    from supertokens_python.recipe.multitenancy.interfaces import (
        EmailPasswordConfig,
        PasswordlessConfig,
        ThirdPartyConfig,
    )


class SessionInfo:
    def __init__(self, info: SessionInformationResult) -> None:
        self.session_handle = info.session_handle
        self.user_id = info.user_id
        self.session_data_in_database = info.session_data_in_database
        self.expiry = info.expiry
        self.access_token_payload = info.custom_claims_in_access_token_payload
        self.time_created = info.time_created
        self.tenant_id = info.tenant_id


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_dashboard_bundle_location(self, user_context: Dict[str, Any]) -> str:
        pass

    @abstractmethod
    async def should_allow_access(
        self,
        request: BaseRequest,
        config: DashboardConfig,
        user_context: Dict[str, Any],
    ) -> bool:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: DashboardConfig,
        recipe_implementation: RecipeInterface,
        app_info: AppInfo,
    ):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config: DashboardConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.app_info = app_info


class APIInterface:
    def __init__(self):
        # undefined should be allowed
        self.dashboard_get: Optional[
            Callable[[APIOptions, Dict[str, Any]], Awaitable[str]]
        ] = None


class DashboardUsersGetResponse(APIResponse):
    status: str = "OK"

    def __init__(
        self,
        users: Union[List[User], List[UserWithMetadata]],
        next_pagination_token: Optional[str],
    ):
        self.users = users
        self.next_pagination_token = next_pagination_token

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "users": [u.to_json() for u in self.users],
            "nextPaginationToken": self.next_pagination_token,
        }


class DashboardListTenantItem:
    def __init__(
        self,
        tenant_id: str,
        emailpassword: EmailPasswordConfig,
        passwordless: PasswordlessConfig,
        third_party: ThirdPartyConfig,
    ):
        self.tenant_id = tenant_id
        self.emailpassword = emailpassword
        self.passwordless = passwordless
        self.third_party = third_party

    def to_json(self):
        res = {
            "tenantId": self.tenant_id,
            "emailPassword": self.emailpassword.to_json(),
            "passwordless": self.passwordless.to_json(),
            "thirdParty": self.third_party.to_json(),
        }

        return res


class DashboardListTenantsGetResponse(APIResponse):
    status: str = "OK"

    def __init__(self, tenants: List[DashboardListTenantItem]) -> None:
        self.tenants = tenants

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "tenants": [t.to_json() for t in self.tenants],
        }


class UserCountGetAPIResponse(APIResponse):
    status: str = "OK"

    def __init__(self, count: int):
        self.count = count

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "count": self.count}


class UserGetAPIOkResponse(APIResponse):
    status: str = "OK"

    def __init__(self, recipe_id: str, user: UserWithMetadata):
        self.recipe_id = recipe_id
        self.user = user

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "recipeId": self.recipe_id,
            "user": self.user.to_json(),
        }


class UserGetAPINoUserFoundError(APIResponse):
    status: str = "NO_USER_FOUND_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserGetAPIRecipeNotInitialisedError(APIResponse):
    status: str = "RECIPE_NOT_INITIALISED"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class FeatureNotEnabledError(APIResponse):
    status: str = "FEATURE_NOT_ENABLED_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserMetadataGetAPIOkResponse(APIResponse):
    status: str = "OK"

    def __init__(self, data: Dict[str, Any]) -> None:
        self.data = data

    def to_json(self) -> Dict[str, Any]:
        return {"status": "OK", "data": self.data}


class UserSessionsGetAPIResponse(APIResponse):
    status: str = "OK"

    def __init__(self, sessions: List[SessionInfo]):
        self.sessions = [
            {
                "accessTokenPayload": s.access_token_payload,
                "expiry": s.expiry,
                "sessionDataInDatabase": s.session_data_in_database,
                "tenantId": s.tenant_id,
                "timeCreated": s.time_created,
                "userId": s.user_id,
                "sessionHandle": s.session_handle,
            }
            for s in sessions
        ]

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "sessions": self.sessions}


class UserEmailVerifyGetAPIResponse(APIResponse):
    status: str = "OK"

    def __init__(self, is_verified: bool):
        self.is_verified = is_verified

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "isVerified": self.is_verified}


class UserDeleteAPIResponse(APIResponse):
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserEmailVerifyPutAPIResponse(APIResponse):
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserPasswordPutAPIResponse(APIResponse):
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserPasswordPutAPIInvalidPasswordErrorResponse(APIResponse):
    status: str = "INVALID_PASSWORD_ERROR"

    def __init__(self, error: str) -> None:
        self.error = error

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "error": self.error}


class UserSessionsPostAPIResponse(APIResponse):
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserEmailVerifyTokenPostAPIOkResponse(APIResponse):
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserEmailVerifyTokenPostAPIEmailAlreadyVerifiedErrorResponse(APIResponse):
    status: str = "EMAIL_ALREADY_VERIFIED_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserMetadataPutAPIResponse(APIResponse):
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserPutAPIOkResponse(APIResponse):
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserPutAPIInvalidEmailErrorResponse(APIResponse):
    status: str = "INVALID_EMAIL_ERROR"

    def __init__(self, error: str) -> None:
        self.error = error

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "error": self.error}


class UserPutAPIEmailAlreadyExistsErrorResponse(APIResponse):
    status: str = "EMAIL_ALREADY_EXISTS_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserPutPhoneAlreadyExistsAPIResponse(APIResponse):
    status: str = "PHONE_ALREADY_EXISTS_ERROR"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class UserPutAPIInvalidPhoneErrorResponse(APIResponse):
    status: str = "INVALID_PHONE_ERROR"

    def __init__(self, error: str) -> None:
        self.error = error

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status, "error": self.error}


class SignOutOK(APIResponse):
    status: str = "OK"

    def to_json(self):
        return {"status": self.status}


class SearchTagsOK(APIResponse):
    status: str = "OK"
    tags: List[str]

    def __init__(self, tags: List[str]) -> None:
        self.tags = tags

    def to_json(self):
        return {"status": self.status, "tags": self.tags}


class AnalyticsResponse(APIResponse):
    status: str = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}
