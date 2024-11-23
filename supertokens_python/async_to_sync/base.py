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

from typing import Any, Coroutine, TypeVar

_T = TypeVar("_T")


def sync(co: Coroutine[Any, Any, _T]) -> _T:
    from supertokens_python import supertokens  # pylint: disable=cyclic-import

    st = supertokens.Supertokens.get_instance()
    handler = st.async_handler

    return handler.run_as_sync(co)
