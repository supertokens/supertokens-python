"""
Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

type_string = {
    'type': 'string'
}
type_number = {
    'type': 'number'
}
type_boolean = {
    'type': 'boolean'
}
type_object = {
    'type': 'object'
}
type_null = {
    'type': 'null'
}
same_site = {
    'type': 'string',
    'enum': ['None', 'Lax', 'Strict']
}
user_id = type_string
user_data_in_jwt = type_object
user_data_in_database = type_object
session_handle = type_string
anti_csrf_token = type_string
session = {
    'type': 'object',
    'properties': {
        'handle': session_handle,
        'userId': user_id,
        'userDataInJWT': user_data_in_jwt
    },
    'additionalProperties': False,
    'required': ['handle', 'userId', 'userDataInJWT']
}
token = {
    'type': 'object',
    'properties': {
        'token': type_string,
        'expiry': type_number,
        'createdTime': type_number,
        'cookiePath': type_string,
        'cookieSecure': type_boolean,
        'domain': type_string,
        'sameSite': same_site
    }
}
session_without_anti_csrf = {
    'type': 'object',
    'properties': {
        'session': session,
        'accessToken': token,
        'refreshToken': token,
        'idRefreshToken': token,
        'antiCsrfToken': type_null
    },
    'additionalProperties': False,
    'required': ['session', 'accessToken', 'refreshToken', 'idRefreshToken', 'antiCsrfToken']
}
session_with_anti_csrf = {
    'type': 'object',
    'properties': {
        'session': session,
        'accessToken': token,
        'refreshToken': token,
        'idRefreshToken': token,
        'antiCsrfToken': anti_csrf_token
    },
    'additionalProperties': False,
    'required': ['session', 'accessToken', 'refreshToken', 'idRefreshToken', 'antiCsrfToken']
}
session_verify_without_access_token = {
    'type': 'object',
    'properties': {
        'session': session
    },
    'additionalProperties': False,
    'required': ['session']
}
session_verify_with_access_token = {
    'type': 'object',
    'properties': {
        'session': session,
        'accessToken': token,
    },
    'additionalProperties': False,
    'required': ['session', 'accessToken']
}
