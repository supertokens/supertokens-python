from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union

from supertokens_python.recipe.emailpassword import interfaces as EPInterfaces
from supertokens_python.recipe.emailpassword.types import FormField
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.thirdparty import interfaces as ThirdPartyInterfaces
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.types import APIResponse, GeneralErrorResponse

from .types import User

ThirdPartyAPIOptions = ThirdPartyInterfaces.APIOptions
EmailPasswordAPIOptions = EPInterfaces.APIOptions

# Exporting re-used classes
CreateResetPasswordOkResult = EPInterfaces.CreateResetPasswordOkResult
CreateResetPasswordWrongUserIdError = EPInterfaces.CreateResetPasswordWrongUserIdError
EmailPasswordEmailExistsGetOkResult = EPInterfaces.EmailExistsGetOkResult
GeneratePasswordResetTokenPostOkResult = (
    EPInterfaces.GeneratePasswordResetTokenPostOkResult
)
PasswordResetPostInvalidTokenResponse = (
    EPInterfaces.PasswordResetPostInvalidTokenResponse
)
PasswordResetPostOkResult = EPInterfaces.PasswordResetPostOkResult
ResetPasswordUsingTokenInvalidTokenError = (
    EPInterfaces.ResetPasswordUsingTokenInvalidTokenError
)
ResetPasswordUsingTokenOkResult = EPInterfaces.ResetPasswordUsingTokenOkResult
EmailPasswordSignInPostWrongCredentialsError = (
    EPInterfaces.SignInPostWrongCredentialsError
)
EmailPasswordSignInWrongCredentialsError = EPInterfaces.SignInWrongCredentialsError
EmailPasswordSignUpEmailAlreadyExistsError = EPInterfaces.SignUpEmailAlreadyExistsError
EmailPasswordSignUpPostEmailAlreadyExistsError = (
    EPInterfaces.SignUpPostEmailAlreadyExistsError
)
UpdateEmailOrPasswordEmailAlreadyExistsError = (
    EPInterfaces.UpdateEmailOrPasswordEmailAlreadyExistsError
)
UpdateEmailOrPasswordOkResult = EPInterfaces.UpdateEmailOrPasswordOkResult
UpdateEmailOrPasswordUnknownUserIdError = (
    EPInterfaces.UpdateEmailOrPasswordUnknownUserIdError
)

AuthorisationUrlGetOkResult = ThirdPartyInterfaces.AuthorisationUrlGetOkResult
ThirdPartySignInUpPostNoEmailGivenByProviderResponse = (
    ThirdPartyInterfaces.SignInUpPostNoEmailGivenByProviderResponse
)


class ThirdPartySignInUpOkResult:
    def __init__(self, user: User, created_new_user: bool):
        self.user = user
        self.created_new_user = created_new_user


class EmailPasswordSignUpOkResult:
    def __init__(self, user: User):
        self.user = user


class EmailPasswordSignInOkResult:
    def __init__(self, user: User):
        self.user = user


class RecipeInterface(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def get_user_by_id(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
        pass

    @abstractmethod
    async def get_users_by_email(
        self, email: str, user_context: Dict[str, Any]
    ) -> List[User]:
        pass

    @abstractmethod
    async def get_user_by_thirdparty_info(
        self,
        third_party_id: str,
        third_party_user_id: str,
        user_context: Dict[str, Any],
    ) -> Union[User, None]:
        pass

    @abstractmethod
    async def thirdparty_sign_in_up(
        self,
        third_party_id: str,
        third_party_user_id: str,
        email: str,
        user_context: Dict[str, Any],
    ) -> ThirdPartySignInUpOkResult:
        pass

    @abstractmethod
    async def emailpassword_sign_in(
        self, email: str, password: str, user_context: Dict[str, Any]
    ) -> Union[EmailPasswordSignInOkResult, EmailPasswordSignInWrongCredentialsError]:
        pass

    @abstractmethod
    async def emailpassword_sign_up(
        self, email: str, password: str, user_context: Dict[str, Any]
    ) -> Union[EmailPasswordSignUpOkResult, EmailPasswordSignUpEmailAlreadyExistsError]:
        pass

    @abstractmethod
    async def create_reset_password_token(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[CreateResetPasswordOkResult, CreateResetPasswordWrongUserIdError]:
        pass

    @abstractmethod
    async def reset_password_using_token(
        self, token: str, new_password: str, user_context: Dict[str, Any]
    ) -> Union[
        ResetPasswordUsingTokenOkResult, ResetPasswordUsingTokenInvalidTokenError
    ]:
        pass

    @abstractmethod
    async def update_email_or_password(
        self,
        user_id: str,
        email: Union[str, None],
        password: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        UpdateEmailOrPasswordOkResult,
        UpdateEmailOrPasswordEmailAlreadyExistsError,
        UpdateEmailOrPasswordUnknownUserIdError,
    ]:
        pass


class ThirdPartySignInUpPostOkResult(APIResponse):
    status: str = "OK"

    def __init__(
        self,
        user: User,
        created_new_user: bool,
        auth_code_response: Dict[str, Any],
        session: SessionContainer,
    ):
        self.user = user
        self.created_new_user = created_new_user
        self.auth_code_response = auth_code_response
        self.session = session

    def to_json(self) -> Dict[str, Any]:
        if self.user.third_party_info is None:
            raise Exception("Third Party Info cannot be None")

        return {
            "status": self.status,
            "user": {
                "id": self.user.user_id,
                "email": self.user.email,
                "timeJoined": self.user.time_joined,
                "thirdParty": {
                    "id": self.user.third_party_info.id,
                    "userId": self.user.third_party_info.user_id,
                },
            },
            "createdNewUser": self.created_new_user,
        }


class EmailPasswordSignInPostOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, user: User, session: SessionContainer):
        self.user = user
        self.session = session

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "user": {
                "id": self.user.user_id,
                "email": self.user.email,
                "timeJoined": self.user.time_joined,
            },
        }


class EmailPasswordSignUpPostOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, user: User, session: SessionContainer):
        self.user = user
        self.session = session

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "user": {
                "id": self.user.user_id,
                "email": self.user.email,
                "timeJoined": self.user.time_joined,
            },
        }


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
    async def authorisation_url_get(
        self,
        provider: Provider,
        api_options: ThirdPartyAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[AuthorisationUrlGetOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def thirdparty_sign_in_up_post(
        self,
        provider: Provider,
        code: str,
        redirect_uri: str,
        client_id: Union[str, None],
        auth_code_response: Union[Dict[str, Any], None],
        api_options: ThirdPartyAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        ThirdPartySignInUpPostOkResult,
        ThirdPartySignInUpPostNoEmailGivenByProviderResponse,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def emailpassword_sign_in_post(
        self,
        form_fields: List[FormField],
        api_options: EmailPasswordAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        EmailPasswordSignInPostOkResult,
        EmailPasswordSignInPostWrongCredentialsError,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def emailpassword_sign_up_post(
        self,
        form_fields: List[FormField],
        api_options: EmailPasswordAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        EmailPasswordSignUpPostOkResult,
        EmailPasswordSignUpPostEmailAlreadyExistsError,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def emailpassword_email_exists_get(
        self,
        email: str,
        api_options: EmailPasswordAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[EmailPasswordEmailExistsGetOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def generate_password_reset_token_post(
        self,
        form_fields: List[FormField],
        api_options: EmailPasswordAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[GeneratePasswordResetTokenPostOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def password_reset_post(
        self,
        form_fields: List[FormField],
        token: str,
        api_options: EmailPasswordAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        PasswordResetPostOkResult,
        PasswordResetPostInvalidTokenResponse,
        GeneralErrorResponse,
    ]:
        pass

    @abstractmethod
    async def apple_redirect_handler_post(
        self,
        code: str,
        state: str,
        api_options: ThirdPartyAPIOptions,
        user_context: Dict[str, Any],
    ):
        pass
