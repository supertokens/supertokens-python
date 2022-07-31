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
from typing import Callable, Optional, Dict, Any, TypeVar

from supertokens_python.types import MaybeAwaitable
from .primitive_claim import PrimitiveClaim, PrimitiveClaimValidators

_T = TypeVar("_T", bound=bool)


class BooleanClaimValidators(PrimitiveClaimValidators[bool]):
    def is_true(self, max_age: Optional[int]):
        if max_age is not None:
            return self.has_fresh_value(True, max_age)
        return self.has_value(True)

    def is_false(self, max_age: Optional[int]):
        if max_age is not None:
            return self.has_fresh_value(False, max_age)
        return self.has_value(False)


class BooleanClaim(PrimitiveClaim[bool]):
    def __init__(
        self,
        key: str,
        fetch_value: Callable[
            [str, Optional[Dict[str, Any]]],
            MaybeAwaitable[Optional[_T]],
        ],
    ):
        super().__init__(key, fetch_value)
        claim = self
        self.validators = BooleanClaimValidators(claim)
