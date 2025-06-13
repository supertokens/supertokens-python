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

# Re-export types to maintain backward compatibility to 0.29
# Do not add more exports here, prefer importing from the actual module
# This syntax unnecessarily pollutes the namespaces and slows down imports

from .base import (
    AccountInfo,
    LoginMethod,
    MaybeAwaitable,
    RecipeUserId,
    User,
)
from .response import APIResponse, GeneralErrorResponse

__all__ = (
    "APIResponse",
    "GeneralErrorResponse",
    "AccountInfo",
    "LoginMethod",
    "MaybeAwaitable",
    "RecipeUserId",
    "User",
)
