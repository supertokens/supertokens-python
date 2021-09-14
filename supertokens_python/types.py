"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

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

type_boolean = {
    'type': 'boolean'
}

INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'supertokens': {
            'type': 'object',
            'properties': {
                'connection_uri': type_string,
                'api_key': type_string
            },
            'required': ['connection_uri'],
            'additionalProperties': False
        },
        'app_info': {
            'type': 'object',
            'properties': {
                'app_name': type_string,
                'website_domain': type_string,
                'api_domain': type_string,
                'api_base_path': type_string,
                'website_base_path': type_string,
                'api_gateway_path': type_string
            },
            'required': ['app_name', 'website_domain', 'api_domain'],
            'additionalProperties': False
        },
        'framework': {
            'type': 'string'
        },
        'recipe_list': {
            'type': 'array'
        },
        'telemetry': type_boolean
    },
    'required': ['supertokens', 'app_info', 'recipe_list', 'framework'],
    'additional_properties': False
}
