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
from os import environ
from typing import List
from enum import Enum


class AllowedProcessStates(Enum):
    CALLING_SERVICE_IN_VERIFY = 1
    CALLING_SERVICE_IN_GET_HANDSHAKE_INFO = 2
    CALLING_SERVICE_IN_GET_API_VERSION = 3
    CALLING_SERVICE_IN_REQUEST_HELPER = 4


class ProcessState:
    __instance = None

    def __init__(self):
        self.history: List[AllowedProcessStates] = []

    @staticmethod
    def get_instance():
        if ProcessState.__instance is None:
            ProcessState.__instance = ProcessState()
        return ProcessState.__instance

    def add_state(self, state: AllowedProcessStates):
        if ("SUPERTOKENS_ENV" in environ) and (environ["SUPERTOKENS_ENV"] == "testing"):
            self.history.append(state)

    def reset(self):
        self.history = []
