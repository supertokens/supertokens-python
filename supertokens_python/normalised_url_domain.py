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

from .utils import is_an_ip_address

if TYPE_CHECKING:
    pass
from .exceptions import raise_general_exception


class NormalisedURLDomain:
    def __init__(self, url: str):
        self.__value = normalise_domain_path_or_throw_error(url)

    def get_as_string_dangerous(self):
        return self.__value


def normalise_domain_path_or_throw_error(
    input_str: str, ignore_protocol: bool = False
) -> str:
    input_str = input_str.strip().lower()

    try:
        if (
            (not input_str.startswith("http://"))
            and (not input_str.startswith("https://"))
            and (not input_str.startswith("supertokens://"))
        ):
            raise Exception("converting to proper URL")
        url_obj = urlparse(input_str)

        if ignore_protocol:
            if url_obj.hostname is None:
                raise Exception("Should never come here")
            if url_obj.hostname.startswith("localhost") or is_an_ip_address(
                url_obj.hostname
            ):
                input_str = "http://" + url_obj.netloc
            else:
                input_str = "https://" + url_obj.netloc
        else:
            input_str = url_obj.scheme + "://" + url_obj.netloc

        return input_str
    except Exception:
        pass

    if input_str.startswith("/"):
        raise_general_exception("Please provide a valid domain name")

    if input_str.startswith("."):
        input_str = input_str[1:]

    if (
        ("." in input_str or input_str.startswith("localhost"))
        and (not input_str.startswith("http://"))
        and (not input_str.startswith("https://"))
    ):
        input_str = "https://" + input_str
        try:
            urlparse(input_str)
            return normalise_domain_path_or_throw_error(input_str, True)
        except Exception:
            pass
    raise_general_exception("Please provide a valid domain name")
