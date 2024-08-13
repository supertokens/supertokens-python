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

from typing import Dict, Any, Union, List, Optional, Callable
from .interfaces import RecipeInterface, APIInterface


class MFARequirementList(List[Union[Dict[str, List[str]], str]]):
    def __init__(self, *args: Union[str, Dict[str, List[str]]]):
        super().__init__()
        for arg in args:
            if isinstance(arg, str):
                self.append(arg)
            else:
                if "oneOf" in arg:
                    self.append({"oneOf": arg["oneOf"]})
                elif "allOfInAnyOrder" in arg:
                    self.append({"allOfInAnyOrder": arg["allOfInAnyOrder"]})
                else:
                    raise ValueError("Invalid dictionary format")


class MFAClaimValue:
    c: Dict[str, Any]
    v: bool

    def __init__(self, c: Dict[str, Any], v: bool):
        self.c = c
        self.v = v


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


class AccountLinkingConfig:
    def __init__(
        self,
        first_factors: Optional[List[str]],
        override: OverrideConfig,
    ):
        self.first_factors = first_factors
        self.override = override
