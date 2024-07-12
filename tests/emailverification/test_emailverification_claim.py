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

from supertokens_python.recipe.emailverification import EmailVerificationClaim
import time


def test_claim_value_should_be_fetched_if_it_is_None():
    validator = EmailVerificationClaim.validators.is_verified()

    should_refetch_none = validator.should_refetch({}, {})
    assert should_refetch_none == True


def test_claim_value_should_be_fetched_as_per_max_age_if_provided():
    validator = EmailVerificationClaim.validators.is_verified(10, 200)

    payload = {
        "st-ev": {
            "v": True,
            "t": int(time.time() * 1000) - 199 * 1000,
        }
    }

    should_refetch_valid = validator.should_refetch(payload, {})
    assert should_refetch_valid == False

    payload = {
        "st-ev": {
            "v": True,
            "t": int(time.time() * 1000) - 201 * 1000,
        }
    }

    should_refetch_expired = validator.should_refetch(payload, {})
    assert should_refetch_expired == True


def test_claim_value_should_be_fetched_as_per_refetch_time_on_false_if_provided():
    validator = EmailVerificationClaim.validators.is_verified(8)

    payload = {
        "st-ev": {
            "v": False,
            "t": int(time.time() * 1000) - 7 * 1000,
        }
    }

    should_refetch_valid = validator.should_refetch(payload, {})
    assert should_refetch_valid == False

    payload = {
        "st-ev": {
            "v": False,
            "t": int(time.time() * 1000) - 9 * 1000,
        }
    }

    should_refetch_expired = validator.should_refetch(payload, {})
    assert should_refetch_expired == True


def test_claim_value_should_be_fetched_as_per_default_refetch_time_on_false_if_not_provided():
    validator = EmailVerificationClaim.validators.is_verified()

    # NOTE: the default value of refetchTimeOnFalseInSeconds is 10 seconds
    payload = {
        "st-ev": {
            "v": False,
            "t": int(time.time() * 1000) - 9 * 1000,
        }
    }

    should_refetch_valid = validator.should_refetch(payload, {})
    assert should_refetch_valid == False

    payload = {
        "st-ev": {
            "v": False,
            "t": int(time.time() * 1000) - 11 * 1000,
        }
    }

    should_refetch_expired = validator.should_refetch(payload, {})
    assert should_refetch_expired == True
