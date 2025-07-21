# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
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

REGISTER_OPTIONS_API = "/webauthn/options/register"

SIGNIN_OPTIONS_API = "/webauthn/options/signin"

SIGN_UP_API = "/webauthn/signup"

SIGN_IN_API = "/webauthn/signin"

GENERATE_RECOVER_ACCOUNT_TOKEN_API = "/user/webauthn/reset/token"

RECOVER_ACCOUNT_API = "/user/webauthn/reset"

SIGNUP_EMAIL_EXISTS_API = "/webauthn/email/exists"

REGISTER_CREDENTIAL_API = "/webauthn/credential"

# 60 seconds (60 * 1000ms)
DEFAULT_REGISTER_OPTIONS_TIMEOUT = 60000
DEFAULT_REGISTER_OPTIONS_ATTESTATION = "none"
DEFAULT_REGISTER_OPTIONS_RESIDENT_KEY = "required"
DEFAULT_REGISTER_OPTIONS_USER_VERIFICATION = "preferred"
DEFAULT_REGISTER_OPTIONS_USER_PRESENCE = True
# -8 = EdDSA, -7 = ES256, -257 = RS256
DEFAULT_REGISTER_OPTIONS_SUPPORTED_ALGORITHM_IDS = [-8, -7, -257]

# 60 seconds (60 * 1000ms)
DEFAULT_SIGNIN_OPTIONS_TIMEOUT = 60000
DEFAULT_SIGNIN_OPTIONS_USER_VERIFICATION = "preferred"
DEFAULT_SIGNIN_OPTIONS_USER_PRESENCE = True
