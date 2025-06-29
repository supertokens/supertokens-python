# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing_extensions import Literal

from supertokens_python.types.response import StatusReasonResponseBaseModel


class LinkingToSessionUserFailedError(
    StatusReasonResponseBaseModel[
        Literal["LINKING_TO_SESSION_USER_FAILED"],
        Literal[
            "EMAIL_VERIFICATION_REQUIRED",
            "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
            "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
            "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
            "INPUT_USER_IS_NOT_A_PRIMARY_USER",
        ],
    ]
):
    status: Literal["LINKING_TO_SESSION_USER_FAILED"] = "LINKING_TO_SESSION_USER_FAILED"
    reason: Literal[
        "EMAIL_VERIFICATION_REQUIRED",
        "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
        "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
        "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR",
        "INPUT_USER_IS_NOT_A_PRIMARY_USER",
    ]
