from abc import ABC, abstractmethod
from typing import Union, List

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal

from supertokens_python.recipe.emailpassword.interfaces import CreateResetPasswordResult, ResetPasswordUsingTokenResult, \
    UpdateEmailOrPasswordResult, SignInResult, SignUpResult, EmailExistsGetResponse, \
    GeneratePasswordResetTokenPostResponse, PasswordResetPostResponse, APIOptions as EmailPasswordApiOptions
from supertokens_python.recipe.emailpassword.types import FormField
from supertokens_python.recipe.thirdparty.interfaces import SignInUpResult, APIOptions as ThirdPartyApiOptions, \
    AuthorisationUrlGetResponse
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.recipe.thirdpartyemailpassword.types import User, UsersResponse


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
    async def update_email_or_password(self, user_id: str, email: str = None,
                                       password: str = None) -> UpdateEmailOrPasswordResult:
        pass


class SignInUpPostResponse(ABC):
    def __init__(self, recipe_type: Literal['emailpassword', 'thirdparty'],
                 status: Literal[
                     'OK', 'NO_EMAIL_GIVEN_BY_PROVIDER', 'WRONG_CREDENTIALS_ERROR', 'EMAIL_ALREADY_EXISTS_ERROR'],
                 user: Union[User, None] = None,
                 created_new_user: Union[bool, None] = None, auth_code_response: any = None,
                 error: Union[str, None] = None):
        self.type = recipe_type
        self.status = status
        self.is_ok = False
        self.is_no_email_given_by_provider = False
        self.is_wrong_credentials_error = False
        self.is_email_already_exists_error = False
        self.user = user
        self.created_new_user = created_new_user
        self.error = error
        self.auth_code_response = auth_code_response

    @abstractmethod
    def to_json(self):
        pass


class SignInUpPostThirdPartyOkResponse(SignInUpPostResponse):
    def __init__(self, user: User, created_new_user: bool,
                 auth_code_response: any):
        super().__init__('thirdparty', 'OK', user, created_new_user, auth_code_response)
        self.is_ok = True

    def to_json(self):
        return {
            'status': self.status,
            'user': {
                'id': self.user.user_id,
                'email': self.user.email,
                'timeJoined': self.user.time_joined,
                'thirdParty': {
                    'id': self.user.third_party_info.id,
                    'userId': self.user.third_party_info.user_id
                }
            },
            'createdNewUser': self.created_new_user
        }


class SignInUpPostThirdPartyNoEmailGivenByProviderResponse(
        SignInUpPostResponse):
    def __init__(self):
        super().__init__('thirdparty', 'NO_EMAIL_GIVEN_BY_PROVIDER')
        self.is_no_email_given_by_provider = True

    def to_json(self):
        return {
            'status': self.status
        }


class SignInUpPostEmailPasswordOkResponse(SignInUpPostResponse):
    def __init__(self, user: User, created_new_user: bool):
        super().__init__('emailpassword', 'OK', user, created_new_user)
        self.is_ok = True

    def to_json(self):
        return {
            'status': self.status,
            'user': {
                'id': self.user.user_id,
                'email': self.user.email,
                'timeJoined': self.user.time_joined
            },
            'createdNewUser': self.created_new_user
        }


class SignInUpPostEmailPasswordWrongCredentialsErrorResponse(
        SignInUpPostResponse):
    def __init__(self):
        super().__init__('emailpassword', 'WRONG_CREDENTIALS_ERROR')
        self.is_wrong_credentials_error = True

    def to_json(self):
        return {
            'status': self.status
        }


class SignUpPostEmailPasswordEmailAlreadyExistsErrorResponse(
        SignInUpPostResponse):
    def __init__(self):
        super().__init__('emailpassword', 'EMAIL_ALREADY_EXISTS_ERROR')
        self.is_email_already_exists_error = True

    def to_json(self):
        return {
            'status': self.status
        }


class SignInUpAPIInput:
    def __init__(self, recipe_type: Literal['emailpassword', 'thirdparty'],
                 options: Union[EmailPasswordApiOptions, ThirdPartyApiOptions], provider: Union[Provider, None] = None,
                 code: Union[str, None] = None, redirect_uri: Union[str, None] = None, is_sign_in: bool = False,
                 form_fields: Union[List[FormField], None] = None):
        self.type = recipe_type
        self.options = options
        self.provider = provider
        self.code = code
        self.redirect_uri = redirect_uri
        self.is_sign_in = is_sign_in
        self.form_fields = form_fields


class APIInterface(ABC):
    def __init__(self):
        self.disable_sign_in_up_post = False
        self.disable_authorisation_url_get = False
        self.disable_email_exists_get = False
        self.disable_generate_password_reset_token_post = False
        self.disable_password_reset_post = False

    @abstractmethod
    async def authorisation_url_get(self, provider: Provider,
                                    api_options: ThirdPartyApiOptions) -> AuthorisationUrlGetResponse:
        pass

    @abstractmethod
    async def sign_in_up_post(self, api_options: SignInUpAPIInput) -> SignInUpPostResponse:
        pass

    @abstractmethod
    async def email_exists_get(self, email: str, api_options: EmailPasswordApiOptions) -> EmailExistsGetResponse:
        pass

    @abstractmethod
    async def generate_password_reset_token_post(self, form_fields: List[FormField],
                                                 api_options: EmailPasswordApiOptions) -> GeneratePasswordResetTokenPostResponse:
        pass

    @abstractmethod
    async def password_reset_post(self, token: str, form_fields: List[FormField],
                                  api_options: EmailPasswordApiOptions) -> PasswordResetPostResponse:
        pass
