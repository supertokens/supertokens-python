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

from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    pass
from .exceptions import raise_general_exception


class NormalisedURLPath:
    def __init__(self, url: str):
        self.__value = normalise_url_path_or_throw_error(url)

    def startswith(self, other: NormalisedURLPath) -> bool:
        return self.__value.startswith(other.get_as_string_dangerous())

    def append(self, other: NormalisedURLPath) -> NormalisedURLPath:
        return NormalisedURLPath(self.__value + other.get_as_string_dangerous())

    def get_as_string_dangerous(self) -> str:
        return self.__value

    def equals(self, other: NormalisedURLPath) -> bool:
        return self.__value == other.get_as_string_dangerous()

    def is_a_recipe_path(self) -> bool:
        parts = self.__value.split("/")
        return (len(parts) > 1 and parts[1] == "recipe") or (
            len(parts) > 2 and parts[2] == "recipe"
        )


def normalise_url_path_or_throw_error(input_str: str) -> str:
    input_str = input_str.strip().lower()

    try:
        if (not input_str.startswith("http://")) and (
            not input_str.startswith("https://")
        ):
            raise Exception("converting to proper URL")
        url_obj = urlparse(input_str)
        input_str = url_obj.path

        if input_str.endswith("/"):
            return input_str[:-1]

        return input_str
    except Exception:
        pass

    if (
        (domain_given(input_str) or input_str.startswith("localhost"))
        and (not input_str.startswith("http://"))
        and (not input_str.startswith("https://"))
    ):
        input_str = "http://" + input_str
        return normalise_url_path_or_throw_error(input_str)

    if not input_str.startswith("/"):
        input_str = "/" + input_str

    try:
        urlparse("http://example.com" + input_str)
        return normalise_url_path_or_throw_error("http://example.com" + input_str)
    except Exception:
        raise_general_exception("Please provide a valid URL path")


def domain_given(input_str: str) -> bool:
    if ("." not in input_str) or (input_str.startswith("/")):
        return False

    try:
        url = urlparse(input_str)
        if url.hostname is None:
            raise Exception("Should never come here")
        return url.hostname.find(".") != -1
    except Exception:
        pass

    try:
        url = urlparse("http://" + input_str)
        if url.hostname is None:
            raise Exception("Should never come here")
        return url.hostname.find(".") != -1
    except Exception:
        pass

    return False
