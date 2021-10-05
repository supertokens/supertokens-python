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

from supertokens_python.jwt import get_payload
from supertokens_python.utils import utf_base64encode
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from json import (
    dumps
)
from base64 import b64encode
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme


def test_jwt_get_payload():
    key_pair = RSA.generate(bits=2048)
    pub_key = key_pair.publickey().export_key().decode(
        'utf-8').split('-----BEGIN PUBLIC KEY-----\n')[1]
    pub_key = pub_key.split('-----END PUBLIC KEY-----')[0]
    pub_key = ''.join(pub_key.split('\n'))

    data = {'a': 'test'}
    payload = utf_base64encode(dumps(data))
    header = utf_base64encode(dumps({
        'alg': 'RS256',
        'typ': 'JWT',
        'version': '2'
    }, separators=(',', ':'), sort_keys=True))
    msg = header + '.' + payload
    hashed_msg = SHA256.new(msg.encode('utf-8'))
    signer = PKCS115_SigScheme(key_pair)
    signature = b64encode(signer.sign(hashed_msg)).decode('utf-8')
    token = msg + '.' + signature

    payload_from_func = get_payload(token, pub_key)
    assert payload_from_func == data
