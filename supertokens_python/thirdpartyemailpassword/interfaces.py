from abc import ABC, abstractmethod
from typing import Union, List

from supertokens_python.emailpassword.interfaces import CreateResetPasswordResult, ResetPasswordUsingTokenResult, \
    UpdateEmailOrPasswordResult, SignInResult, SignUpResult
from supertokens_python.thirdparty.provider import Provider
from supertokens_python.thirdpartyemailpassword.types import User, UsersResponse, SignInResponse, \
    SignUpResponse
from supertokens_python.thirdparty.interfaces import SignInUpResult, APIOptions, AuthorisationUrlGetResponse, \
    SignInUpPostResponse, EmailExistsResponse, GeneratePasswordResetTokenResponse, PasswordResetResponse

from supertokens_python.thirdparty.interfaces import APIOptions as ThirdPartyAPIOptions
from supertokens_python.emailpassword.interfaces import APIOptions as EmailPasswordAPIOptions


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_users_by_email(self, email: str) -> List[User]:
        pass

    @abstractmethod
    async def get_user_by_thirdparty_info(self, third_party_id: str, third_party_user_id: str) -> Union[User, None]:
        pass

    @abstractmethod
    async def sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                         email_verified: bool) -> SignInUpResult:
        pass

    @abstractmethod
    async def sign_in(self, email: str, password: str) -> SignInResult:
        pass

    @abstractmethod
    async def sign_up(self, email: str, password: str) -> SignUpResult:
        pass

    @abstractmethod
    async def get_users_oldest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        pass

    @abstractmethod
    async def get_users_newest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        pass

    @abstractmethod
    async def get_user_count(self) -> int:
        pass

    @abstractmethod
    async def create_reset_password_token(self, user_id: str) -> CreateResetPasswordResult:
        pass

    @abstractmethod
    async def reset_password_using_token(self, token: str, new_password: str) -> ResetPasswordUsingTokenResult:
        pass

    @abstractmethod
    async def update_password_or_email(self, user_id: str, email: str = None, password: str = None) -> UpdateEmailOrPasswordResult:
        pass


class APIInterface(ABC):
    def __init__(self):
        self.disable_sign_in_up_post = False
        self.disable_authorisation_url_get = False

    @abstractmethod
    async def authorisation_url_get(self, provider: Provider, api_options: APIOptions) -> AuthorisationUrlGetResponse:
        pass

    @abstractmethod
    async def sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str,
                              api_options: APIOptions) -> SignInUpPostResponse:
        pass