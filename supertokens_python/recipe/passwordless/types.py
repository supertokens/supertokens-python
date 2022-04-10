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
from typing import List, Union


class User:
    """User.
    """

    def __init__(self, user_id: str,
                 email: Union[str, None], phone_number: Union[str, None], time_joined: int):
        """__init__.

        Parameters
        ----------
        user_id : str
            user_id
        email : Union[str, None]
            email
        phone_number : Union[str, None]
            phone_number
        time_joined : int
            time_joined
        """
        self.user_id: str = user_id
        self.email: Union[str, None] = email
        self.phone_number: Union[str, None] = phone_number
        self.time_joined: int = time_joined


class DeviceCode:
    """DeviceCode.
    """

    def __init__(self, code_id: str, time_created: str, code_life_time: int):
        """__init__.

        Parameters
        ----------
        code_id : str
            code_id
        time_created : str
            time_created
        code_life_time : int
            code_life_time
        """
        self.code_id = code_id
        self.time_created = time_created
        self.code_life_time = code_life_time


class DeviceType:
    """DeviceType.
    """

    def __init__(self,
                 pre_auth_session_id: str,
                 failed_code_input_attempt_count: int,
                 codes: List[DeviceCode],
                 email: Union[str, None] = None,
                 phone_number: Union[str, None] = None
                 ):
        """__init__.

        Parameters
        ----------
        pre_auth_session_id : str
            pre_auth_session_id
        failed_code_input_attempt_count : int
            failed_code_input_attempt_count
        codes : List[DeviceCode]
            codes
        email : Union[str, None]
            email
        phone_number : Union[str, None]
            phone_number
        """
        self.pre_auth_session_id = pre_auth_session_id
        self.failed_code_input_attempt_count = failed_code_input_attempt_count
        self.codes = codes
        self.email = email
        self.phone_number = phone_number
