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

type_string = {
    'type': 'string'
}

type_boolean = {
    'type': 'boolean'
}

type_number = {
    'type': 'number'
}

type_any = {}

INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'cookie_secure': type_boolean,
        'cookie_same_site': type_string,
        'session_expired_status_code': type_number,
        'cookie_domain': type_string,
        'error_handlers': {
            'type': 'object',
            'properties': {
                'on_unauthorised': type_any,
                'on_token_theft_detected': type_any
            },
            'additionalProperties': False
        },
        'anti_csrf': {
            'type': 'string',
            'enum': ['VIA_TOKEN', 'VIA_CUSTOM_HEADER', 'NONE']
        },
        'override': {
            'type': 'object',
            'properties': {
                'functions': type_any,
                'apis': type_any
            },
            'additionalProperties': False
        }
    },
    'required': [],
    'additionalProperties': False
}
