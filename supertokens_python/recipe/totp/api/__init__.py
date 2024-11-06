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
from .create_device import handle_create_device_api
from .list_devices import handle_list_devices_api
from .remove_device import handle_remove_device_api
from .verify_device import handle_verify_device_api
from .verify_totp import handle_verify_totp_api

__all__ = [
    "handle_create_device_api",
    "handle_list_devices_api",
    "handle_remove_device_api",
    "handle_verify_device_api",
    "handle_verify_totp_api",
]
