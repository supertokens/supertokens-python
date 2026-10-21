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

# nest_asyncio is only required by the `flask-nest-asyncio` website-test
# matrix variant (and the unit/auth-react/backend-sdk envs that install
# dev-requirements.txt). The other website-test variants run `make with-X`
# without dev-requirements.txt and don't have it installed, so importing
# unconditionally breaks any later `from tests.<...> import ...` in those
# test servers. Make the apply optional.
try:
    import nest_asyncio  # type: ignore
except ImportError:
    pass
else:
    nest_asyncio.apply()  # type: ignore
