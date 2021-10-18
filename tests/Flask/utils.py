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


def extract_all_cookies(response):
    cookie_headers = response.headers.getlist('Set-Cookie')
    cookies = dict()
    for header in cookie_headers:
        attributes = header.split(';')
        cookie = {}
        is_name = True
        name = None
        for attr in attributes:
            split = attr.split('=')
            if is_name:
                name = split[0].strip()
                cookie['value'] = split[1]
                is_name = False
            else:
                cookie[split[0].strip().lower()] = split[1] if len(
                    split) > 1 else True
        cookies[name] = cookie
    return cookies
