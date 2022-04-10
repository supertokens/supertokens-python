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
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Union

from supertokens_python.async_to_sync_wrapper import sync

from .utils import SessionConfig

from typing_extensions import Literal
if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse


class SessionObj:
    """SessionObj.
    """

    def __init__(self, handle: str, user_id: str, user_data_in_jwt: Dict[str, Any]):
        """__init__.

        Parameters
        ----------
        handle : str
            handle
        user_id : str
            user_id
        user_data_in_jwt : Dict[str, Any]
            user_data_in_jwt
        """
        self.handle = handle
        self.user_id = user_id
        self.user_data_in_jwt = user_data_in_jwt


class AccessTokenObj:
    """AccessTokenObj.
    """

    def __init__(self, token: str, expiry: int, created_time: int):
        """__init__.

        Parameters
        ----------
        token : str
            token
        expiry : int
            expiry
        created_time : int
            created_time
        """
        self.token = token
        self.expiry = expiry
        self.created_time = created_time


class RegenerateAccessTokenResult(ABC):
    """RegenerateAccessTokenResult.
    """

    def __init__(self, status: Literal['OK'], session: SessionObj,
                 access_token: Union[AccessTokenObj, None]):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        session : SessionObj
            session
        access_token : Union[AccessTokenObj, None]
            access_token
        """
        self.status = status
        self.session = session
        self.access_token = access_token


class RegenerateAccessTokenOkResult(RegenerateAccessTokenResult):
    """RegenerateAccessTokenOkResult.
    """

    def __init__(self, session: SessionObj,
                 access_token: Union[AccessTokenObj, None]):
        """__init__.

        Parameters
        ----------
        session : SessionObj
            session
        access_token : Union[AccessTokenObj, None]
            access_token
        """
        super().__init__('OK', session, access_token)


class SessionInformationResult(ABC):
    """SessionInformationResult.
    """

    def __init__(self, status: Literal['OK'], session_handle: str, user_id: str, session_data: Dict[str, Any], expiry: int, access_token_payload: Dict[str, Any], time_created: int):
        """__init__.

        Parameters
        ----------
        status : Literal['OK']
            status
        session_handle : str
            session_handle
        user_id : str
            user_id
        session_data : Dict[str, Any]
            session_data
        expiry : int
            expiry
        access_token_payload : Dict[str, Any]
            access_token_payload
        time_created : int
            time_created
        """
        self.status: Literal['OK'] = status
        self.session_handle: str = session_handle
        self.user_id: str = user_id
        self.session_data: Dict[str, Any] = session_data
        self.expiry: int = expiry
        self.access_token_payload: Dict[str, Any] = access_token_payload
        self.time_created: int = time_created


class RecipeInterface(ABC):
    """RecipeInterface.
    """

    def __init__(self):
        """__init__.
        """
        pass

    @abstractmethod
    async def create_new_session(self, request: Any, user_id: str,
                                 access_token_payload: Union[None, Dict[str, Any]],
                                 session_data: Union[None, Dict[str, Any]], user_context: Dict[str, Any]) -> SessionContainer:
        """create_new_session.

        Parameters
        ----------
        request : Any
            request
        user_id : str
            user_id
        access_token_payload : Union[None, Dict[str, Any]]
            access_token_payload
        session_data : Union[None, Dict[str, Any]]
            session_data
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SessionContainer

        """
        pass

    @abstractmethod
    async def get_session(self, request: Any, anti_csrf_check: Union[bool, None],
                          session_required: bool, user_context: Dict[str, Any]) -> Union[SessionContainer, None]:
        """get_session.

        Parameters
        ----------
        request : Any
            request
        anti_csrf_check : Union[bool, None]
            anti_csrf_check
        session_required : bool
            session_required
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[SessionContainer, None]

        """
        pass

    @abstractmethod
    async def refresh_session(self, request: Any, user_context: Dict[str, Any]) -> SessionContainer:
        """refresh_session.

        Parameters
        ----------
        request : Any
            request
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SessionContainer

        """
        pass

    @abstractmethod
    async def revoke_session(self, session_handle: str, user_context: Dict[str, Any]) -> bool:
        """revoke_session.

        Parameters
        ----------
        session_handle : str
            session_handle
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        bool

        """
        pass

    @abstractmethod
    async def revoke_all_sessions_for_user(self, user_id: str, user_context: Dict[str, Any]) -> List[str]:
        """revoke_all_sessions_for_user.

        Parameters
        ----------
        user_id : str
            user_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        List[str]

        """
        pass

    @abstractmethod
    async def get_all_session_handles_for_user(self, user_id: str, user_context: Dict[str, Any]) -> List[str]:
        """get_all_session_handles_for_user.

        Parameters
        ----------
        user_id : str
            user_id
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        List[str]

        """
        pass

    @abstractmethod
    async def revoke_multiple_sessions(self, session_handles: List[str], user_context: Dict[str, Any]) -> List[str]:
        """revoke_multiple_sessions.

        Parameters
        ----------
        session_handles : List[str]
            session_handles
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        List[str]

        """
        pass

    @abstractmethod
    async def get_session_information(self, session_handle: str, user_context: Dict[str, Any]) -> SessionInformationResult:
        """get_session_information.

        Parameters
        ----------
        session_handle : str
            session_handle
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SessionInformationResult

        """
        pass

    @abstractmethod
    async def update_session_data(self, session_handle: str, new_session_data: Dict[str, Any], user_context: Dict[str, Any]) -> None:
        """update_session_data.

        Parameters
        ----------
        session_handle : str
            session_handle
        new_session_data : Dict[str, Any]
            new_session_data
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        None

        """
        pass

    @abstractmethod
    async def update_access_token_payload(self, session_handle: str,
                                          new_access_token_payload: Dict[str, Any], user_context: Dict[str, Any]) -> None:
        """update_access_token_payload.

        Parameters
        ----------
        session_handle : str
            session_handle
        new_access_token_payload : Dict[str, Any]
            new_access_token_payload
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        None

        """
        pass

    @abstractmethod
    async def get_access_token_lifetime_ms(self, user_context: Dict[str, Any]) -> int:
        """get_access_token_lifetime_ms.

        Parameters
        ----------
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        int

        """
        pass

    @abstractmethod
    async def get_refresh_token_lifetime_ms(self, user_context: Dict[str, Any]) -> int:
        """get_refresh_token_lifetime_ms.

        Parameters
        ----------
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        int

        """
        pass

    @abstractmethod
    async def regenerate_access_token(self,
                                      access_token: str,
                                      new_access_token_payload: Union[Dict[str, Any], None], user_context: Dict[str, Any]) -> RegenerateAccessTokenResult:
        """regenerate_access_token.

        Parameters
        ----------
        access_token : str
            access_token
        new_access_token_payload : Union[Dict[str, Any], None]
            new_access_token_payload
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        RegenerateAccessTokenResult

        """
        pass


class SignOutResponse:
    """SignOutResponse.
    """

    def __init__(self):
        """__init__.
        """
        pass

    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        pass


class SignOutOkayResponse(SignOutResponse):
    """SignOutOkayResponse.
    """

    def __init__(self):
        """__init__.
        """
        self.status = 'OK'
        super().__init__()

    def to_json(self) -> Dict[str, Any]:
        """to_json.

        Parameters
        ----------

        Returns
        -------
        Dict[str, Any]

        """
        return {
            'status': self.status
        }


class APIOptions:
    """APIOptions.
    """

    def __init__(self, request: BaseRequest, response: Union[None, BaseResponse],
                 recipe_id: str, config: SessionConfig, recipe_implementation: RecipeInterface):
        """__init__.

        Parameters
        ----------
        request : BaseRequest
            request
        response : Union[None, BaseResponse]
            response
        recipe_id : str
            recipe_id
        config : SessionConfig
            config
        recipe_implementation : RecipeInterface
            recipe_implementation
        """
        self.request: BaseRequest = request
        self.response: Union[None, BaseResponse] = response
        self.recipe_id: str = recipe_id
        self.config: SessionConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation


class APIInterface(ABC):
    """APIInterface.
    """

    def __init__(self):
        """__init__.
        """
        self.disable_refresh_post = False
        self.disable_signout_post = False

    @abstractmethod
    async def refresh_post(self, api_options: APIOptions, user_context: Dict[str, Any]) -> None:
        """refresh_post.

        Parameters
        ----------
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        None

        """
        pass

    @abstractmethod
    async def signout_post(self, api_options: APIOptions, user_context: Dict[str, Any]) -> SignOutResponse:
        """signout_post.

        Parameters
        ----------
        api_options : APIOptions
            api_options
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        SignOutResponse

        """
        pass

    @abstractmethod
    async def verify_session(self, api_options: APIOptions,
                             anti_csrf_check: Union[bool, None],
                             session_required: bool, user_context: Dict[str, Any]) -> Union[SessionContainer, None]:
        """verify_session.

        Parameters
        ----------
        api_options : APIOptions
            api_options
        anti_csrf_check : Union[bool, None]
            anti_csrf_check
        session_required : bool
            session_required
        user_context : Dict[str, Any]
            user_context

        Returns
        -------
        Union[SessionContainer, None]

        """
        pass


class SessionContainer(ABC):
    """SessionContainer.
    """

    def __init__(self, recipe_implementation: RecipeInterface, access_token: str, session_handle: str, user_id: str, access_token_payload: Dict[str, Any]):
        """__init__.

        Parameters
        ----------
        recipe_implementation : RecipeInterface
            recipe_implementation
        access_token : str
            access_token
        session_handle : str
            session_handle
        user_id : str
            user_id
        access_token_payload : Dict[str, Any]
            access_token_payload
        """
        self.recipe_implementation = recipe_implementation
        self.access_token = access_token
        self.session_handle = session_handle
        self.access_token_payload = access_token_payload
        self.user_id = user_id
        self.new_access_token_info = None
        self.new_refresh_token_info = None
        self.new_id_refresh_token_info = None
        self.new_anti_csrf_token = None
        self.remove_cookies = False

    @abstractmethod
    async def revoke_session(self, user_context: Union[Any, None] = None) -> None:
        """revoke_session.

        Parameters
        ----------
        user_context : Union[Any, None]
            user_context

        Returns
        -------
        None

        """
        pass

    @abstractmethod
    async def get_session_data(self, user_context: Union[Dict[str, Any], None] = None) -> Dict[str, Any]:
        """get_session_data.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        Dict[str, Any]

        """
        pass

    @abstractmethod
    async def update_session_data(self, new_session_data: Dict[str, Any], user_context: Union[Dict[str, Any], None] = None) -> None:
        """update_session_data.

        Parameters
        ----------
        new_session_data : Dict[str, Any]
            new_session_data
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        None

        """
        pass

    @abstractmethod
    async def update_access_token_payload(self, new_access_token_payload: Dict[str, Any], user_context: Union[Dict[str, Any], None] = None) -> None:
        """update_access_token_payload.

        Parameters
        ----------
        new_access_token_payload : Dict[str, Any]
            new_access_token_payload
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        None

        """
        pass

    @abstractmethod
    def get_user_id(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        """get_user_id.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        str

        """
        pass

    @abstractmethod
    def get_access_token_payload(
            self, user_context: Union[Dict[str, Any], None] = None) -> Dict[str, Any]:
        """get_access_token_payload.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        Dict[str, Any]

        """
        pass

    @abstractmethod
    def get_handle(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        """get_handle.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        str

        """
        pass

    @abstractmethod
    def get_access_token(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        """get_access_token.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        str

        """
        pass

    @abstractmethod
    async def get_time_created(self, user_context: Union[Dict[str, Any], None] = None) -> int:
        """get_time_created.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        int

        """
        pass

    @abstractmethod
    async def get_expiry(self, user_context: Union[Dict[str, Any], None] = None) -> int:
        """get_expiry.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        int

        """
        pass

    def sync_get_expiry(self, user_context: Union[Dict[str, Any], None] = None) -> int:
        """sync_get_expiry.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        int

        """
        return sync(self.get_expiry(user_context))

    def sync_revoke_session(
            self, user_context: Union[Dict[str, Any], None] = None) -> None:
        """sync_revoke_session.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        None

        """
        return sync(self.revoke_session(user_context=user_context))

    def sync_get_session_data(
            self, user_context: Union[Dict[str, Any], None] = None) -> Dict[str, Any]:
        """sync_get_session_data.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        Dict[str, Any]

        """
        return sync(self.get_session_data(user_context))

    def sync_get_time_created(
            self, user_context: Union[Dict[str, Any], None] = None) -> int:
        """sync_get_time_created.

        Parameters
        ----------
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        int

        """
        return sync(self.get_time_created(user_context))

    def sync_update_access_token_payload(
            self, new_access_token_payload: Dict[str, Any], user_context: Union[Dict[str, Any], None] = None) -> None:
        """sync_update_access_token_payload.

        Parameters
        ----------
        new_access_token_payload : Dict[str, Any]
            new_access_token_payload
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        None

        """
        return sync(self.update_access_token_payload(new_access_token_payload, user_context))

    def sync_update_session_data(
            self, new_session_data: Dict[str, Any], user_context: Union[Dict[str, Any], None] = None) -> None:
        """sync_update_session_data.

        Parameters
        ----------
        new_session_data : Dict[str, Any]
            new_session_data
        user_context : Union[Dict[str, Any], None]
            user_context

        Returns
        -------
        None

        """
        return sync(self.update_session_data(new_session_data, user_context))

    # This is there so that we can do session["..."] to access some of the members of this class
    def __getitem__(self, item: str):
        """__getitem__.

        Parameters
        ----------
        item : str
            item
        """
        return getattr(self, item)
