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

from typing import Union


def raise_general_exception(
        msg: Union[str, Exception], previous: Union[None, Exception] = None):
    """raise_general_exception.

    Parameters
    ----------
    msg : Union[str, Exception]
        msg
    previous : Union[None, Exception]
        previous
    """
    if isinstance(msg, SuperTokensError):
        raise msg
    if isinstance(msg, Exception):
        raise GeneralError(msg) from None
    raise GeneralError(msg) from previous


def raise_bad_input_exception(msg: str):
    """raise_bad_input_exception.

    Parameters
    ----------
    msg : str
        msg
    """
    raise BadInputError(msg)


class SuperTokensError(Exception):
    """SuperTokensError.
    """

    pass


class GeneralError(SuperTokensError):
    """GeneralError.
    """

    pass


class BadInputError(SuperTokensError):
    """BadInputError.
    """

    pass
