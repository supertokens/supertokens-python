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
from enum import Enum
from os import environ
from typing import List, Optional


class PROCESS_STATE(Enum):
    CALLING_SERVICE_IN_VERIFY = 0
    CALLING_SERVICE_IN_GET_API_VERSION = 1
    CALLING_SERVICE_IN_REQUEST_HELPER = 2
    MULTI_JWKS_VALIDATION = 3
    IS_SIGN_IN_UP_ALLOWED_NO_PRIMARY_USER_EXISTS = 4
    IS_SIGN_UP_ALLOWED_CALLED = 5
    IS_SIGN_IN_ALLOWED_CALLED = 6
    IS_SIGN_IN_UP_ALLOWED_HELPER_CALLED = 7
    ADDING_NO_CACHE_HEADER_IN_FETCH = 8


class ProcessState:
    __instance = None

    def __init__(self):
        self.history: List[PROCESS_STATE] = []

    @staticmethod
    def get_instance():
        if ProcessState.__instance is None:
            ProcessState.__instance = ProcessState()
        return ProcessState.__instance

    def add_state(self, state: PROCESS_STATE):
        if ("SUPERTOKENS_ENV" in environ) and (environ["SUPERTOKENS_ENV"] == "testing"):
            self.history.append(state)

    def reset(self):
        self.history = []

    def get_event_by_last_event_by_name(
        self, state: PROCESS_STATE
    ) -> Optional[PROCESS_STATE]:
        for event in reversed(self.history):
            if event == state:
                return event
        return None

    def wait_for_event(
        self, state: PROCESS_STATE, time_in_ms: int = 7000
    ) -> Optional[PROCESS_STATE]:
        from time import sleep, time

        start_time = time()

        def try_and_get() -> Optional[PROCESS_STATE]:
            result = self.get_event_by_last_event_by_name(state)
            if result is None:
                if (time() - start_time) * 1000 > time_in_ms:
                    return None
                else:
                    sleep(1)
                    return try_and_get()
            else:
                return result

        return try_and_get()
