from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union

from supertokens_python.recipe.emailpassword import interfaces as EPInterfaces
from supertokens_python.recipe.emailpassword.interfaces import (
    CreateResetPasswordResult, EmailExistsGetResponse,
    GeneratePasswordResetTokenPostResponse, PasswordResetPostResponse,
    ResetPasswordUsingTokenResult, SignInPostResponse, SignInResult,
    SignUpPostResponse, SignUpResult, UpdateEmailOrPasswordResult)
from supertokens_python.recipe.emailpassword.types import FormField
from supertokens_python.recipe.thirdparty import \
    interfaces as ThirdPartyInterfaces
from supertokens_python.recipe.thirdparty.interfaces import (
    AuthorisationUrlGetResponse, SignInUpPostResponse, SignInUpResult)
from supertokens_python.recipe.thirdparty.provider import Provider

from .types import User

ThirdPartyAPIOptions = ThirdPartyInterfaces.APIOptions
EmailPasswordAPIOptions = EPInterfaces.APIOptions


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_users_by_email(self, email: str, user_context: Dict[str, Any]) -> List[User]:
        pass

    @abstractmethod
    async def get_user_by_thirdparty_info(self, third_party_id: str,
                                          third_party_user_id: str, user_context: Dict[str, Any]) -> Union[User, None]:
        pass

    @abstractmethod
    async def thirdparty_sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                                    email_verified: bool, user_context: Dict[str, Any]) -> SignInUpResult:
        pass

    @abstractmethod
    async def emailpassword_sign_in(self, email: str, password: str, user_context: Dict[str, Any]) -> SignInResult:
        pass

    @abstractmethod
    async def emailpassword_sign_up(self, email: str, password: str, user_context: Dict[str, Any]) -> SignUpResult:
        pass

    @abstractmethod
    async def create_reset_password_token(self, user_id: str, user_context: Dict[str, Any]) -> CreateResetPasswordResult:
        pass

    @abstractmethod
    async def reset_password_using_token(self, token: str, new_password: str, user_context: Dict[str, Any]) -> ResetPasswordUsingTokenResult:
        pass

    @abstractmethod
    async def update_email_or_password(self, user_id: str, email: Union[str, None],
                                       password: Union[str, None], user_context: Dict[str, Any]) -> UpdateEmailOrPasswordResult:
        pass


class APIInterface(ABC):
    def __init__(self):
        self.disable_thirdparty_sign_in_up_post = False
        self.disable_emailpassword_sign_up_post = False
        self.disable_emailpassword_sign_in_post = False
        self.disable_authorisation_url_get = False
        self.disable_email_exists_get = False
        self.disable_generate_password_reset_token_post = False
        self.disable_password_reset_post = False
        self.disable_apple_redirect_handler_post = False

    @abstractmethod
    async def authorisation_url_get(self, provider: Provider,
                                    api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]) -> AuthorisationUrlGetResponse:
        pass

    @abstractmethod
    async def thirdparty_sign_in_up_post(self, provider: Provider, code: str, redirect_uri: str, client_id: Union[str, None], auth_code_response: Union[Dict[str, Any], None],
                                         api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]) -> SignInUpPostResponse:
        pass

    @abstractmethod
    async def emailpassword_sign_in_post(self, form_fields: List[FormField],
                                         api_options: EmailPasswordAPIOptions, user_context: Dict[str, Any]) -> SignInPostResponse:
        pass

    @abstractmethod
    async def emailpassword_sign_up_post(self, form_fields: List[FormField],
                                         api_options: EmailPasswordAPIOptions, user_context: Dict[str, Any]) -> SignUpPostResponse:
        pass

    @abstractmethod
    async def emailpassword_email_exists_get(self, email: str, api_options: EmailPasswordAPIOptions, user_context: Dict[str, Any]) -> EmailExistsGetResponse:
        pass

    @abstractmethod
    async def generate_password_reset_token_post(self, form_fields: List[FormField],
                                                 api_options: EmailPasswordAPIOptions, user_context: Dict[str, Any]) -> GeneratePasswordResetTokenPostResponse:
        pass

    @abstractmethod
    async def password_reset_post(self, form_fields: List[FormField], token: str,
                                  api_options: EmailPasswordAPIOptions, user_context: Dict[str, Any]) -> PasswordResetPostResponse:
        pass

    @abstractmethod
    async def apple_redirect_handler_post(self, code: str, state: str,
                                          api_options: ThirdPartyAPIOptions, user_context: Dict[str, Any]):
        pass
