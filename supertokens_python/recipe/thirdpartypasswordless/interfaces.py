from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union

from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.thirdparty import interfaces as ThirdPartyInterfaces
from supertokens_python.recipe.thirdparty.provider import Provider
from supertokens_python.types import APIResponse, GeneralErrorResponse

from ..passwordless import interfaces as PlessInterfaces
from .types import User

# Export re-used classes
ThirdPartyAPIOptions = ThirdPartyInterfaces.APIOptions
PasswordlessAPIOptions = PlessInterfaces.APIOptions

ConsumeCodePostRestartFlowError = PlessInterfaces.ConsumeCodePostRestartFlowError
ConsumeCodePostIncorrectUserInputCodeError = (
    PlessInterfaces.ConsumeCodePostIncorrectUserInputCodeError
)
ConsumeCodePostExpiredUserInputCodeError = (
    PlessInterfaces.ConsumeCodePostExpiredUserInputCodeError
)
ConsumeCodeExpiredUserInputCodeError = (
    PlessInterfaces.ConsumeCodeExpiredUserInputCodeError
)
ConsumeCodeIncorrectUserInputCodeError = (
    PlessInterfaces.ConsumeCodeIncorrectUserInputCodeError
)
ConsumeCodeRestartFlowError = PlessInterfaces.ConsumeCodeRestartFlowError
CreateCodeOkResult = PlessInterfaces.CreateCodeOkResult
CreateCodePostOkResult = PlessInterfaces.CreateCodePostOkResult
CreateNewCodeForDeviceOkResult = PlessInterfaces.CreateNewCodeForDeviceOkResult
CreateNewCodeForDeviceRestartFlowError = (
    PlessInterfaces.CreateNewCodeForDeviceRestartFlowError
)
CreateNewCodeForDeviceUserInputCodeAlreadyUsedError = (
    PlessInterfaces.CreateNewCodeForDeviceUserInputCodeAlreadyUsedError
)
PasswordlessDeleteUserInfoOkResult = PlessInterfaces.DeleteUserInfoOkResult
PasswordlessDeleteUserInfoUnknownUserIdError = (
    PlessInterfaces.DeleteUserInfoUnknownUserIdError
)
DeviceType = PlessInterfaces.DeviceType
PasswordlessEmailExistsGetOkResult = PlessInterfaces.EmailExistsGetOkResult
PasswordlessPhoneNumberExistsGetOkResult = PlessInterfaces.PhoneNumberExistsGetOkResult
ResendCodePostOkResult = PlessInterfaces.ResendCodePostOkResult
ResendCodePostRestartFlowError = PlessInterfaces.ResendCodePostRestartFlowError
RevokeAllCodesOkResult = PlessInterfaces.RevokeAllCodesOkResult
RevokeCodeOkResult = PlessInterfaces.RevokeCodeOkResult
PasswordlessUpdateUserEmailAlreadyExistsError = (
    PlessInterfaces.UpdateUserEmailAlreadyExistsError
)
PasswordlessUpdateUserOkResult = PlessInterfaces.UpdateUserOkResult
PasswordlessUpdateUserPhoneNumberAlreadyExistsError = (
    PlessInterfaces.UpdateUserPhoneNumberAlreadyExistsError
)
PasswordlessUpdateUserUnknownUserIdError = PlessInterfaces.UpdateUserUnknownUserIdError

AuthorisationUrlGetOkResult = ThirdPartyInterfaces.AuthorisationUrlGetOkResult
ThirdPartySignInUpOkResult = ThirdPartyInterfaces.SignInUpOkResult
ThirdPartySignInUpPostNoEmailGivenByProviderResponse = (
    ThirdPartyInterfaces.SignInUpPostNoEmailGivenByProviderResponse
)


class ConsumeCodeOkResult:
    def __init__(self, created_new_user: bool, user: User):
        self.created_new_user = created_new_user
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
    async def get_user_by_phone_number(
        self, phone_number: str, user_context: Dict[str, Any]
    ) -> Union[User, None]:
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
    async def create_code(
        self,
        email: Union[None, str],
        phone_number: Union[None, str],
        user_input_code: Union[None, str],
        user_context: Dict[str, Any],
    ) -> CreateCodeOkResult:
        pass

    @abstractmethod
    async def create_new_code_for_device(
        self,
        device_id: str,
        user_input_code: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        CreateNewCodeForDeviceOkResult,
        CreateNewCodeForDeviceRestartFlowError,
        CreateNewCodeForDeviceUserInputCodeAlreadyUsedError,
    ]:
        pass

    @abstractmethod
    async def consume_code(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        ConsumeCodeOkResult,
        ConsumeCodeIncorrectUserInputCodeError,
        ConsumeCodeExpiredUserInputCodeError,
        ConsumeCodeRestartFlowError,
    ]:
        pass

    @abstractmethod
    async def update_passwordless_user(
        self,
        user_id: str,
        email: Union[str, None],
        phone_number: Union[str, None],
        user_context: Dict[str, Any],
    ) -> Union[
        PasswordlessUpdateUserOkResult,
        PasswordlessUpdateUserUnknownUserIdError,
        PasswordlessUpdateUserEmailAlreadyExistsError,
        PasswordlessUpdateUserPhoneNumberAlreadyExistsError,
    ]:
        pass

    @abstractmethod
    async def delete_email_for_passwordless_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[
        PasswordlessDeleteUserInfoOkResult, PasswordlessDeleteUserInfoUnknownUserIdError
    ]:
        pass

    @abstractmethod
    async def delete_phone_number_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> Union[
        PasswordlessDeleteUserInfoOkResult, PasswordlessDeleteUserInfoUnknownUserIdError
    ]:
        pass

    @abstractmethod
    async def revoke_all_codes(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        user_context: Dict[str, Any],
    ) -> RevokeAllCodesOkResult:
        pass

    @abstractmethod
    async def revoke_code(
        self, code_id: str, user_context: Dict[str, Any]
    ) -> RevokeCodeOkResult:
        pass

    @abstractmethod
    async def list_codes_by_email(
        self, email: str, user_context: Dict[str, Any]
    ) -> List[DeviceType]:
        pass

    @abstractmethod
    async def list_codes_by_phone_number(
        self, phone_number: str, user_context: Dict[str, Any]
    ) -> List[DeviceType]:
        pass

    @abstractmethod
    async def list_codes_by_device_id(
        self, device_id: str, user_context: Dict[str, Any]
    ) -> Union[DeviceType, None]:
        pass

    @abstractmethod
    async def list_codes_by_pre_auth_session_id(
        self, pre_auth_session_id: str, user_context: Dict[str, Any]
    ) -> Union[DeviceType, None]:
        pass


class ConsumeCodePostOkResult(APIResponse):
    status: str = "OK"

    def __init__(self, created_new_user: bool, user: User, session: SessionContainer):
        self.created_new_user = created_new_user
        self.user = user
        self.session = session

    def to_json(self):
        user = {"id": self.user.user_id, "time_joined": self.user.time_joined}
        if self.user.email is not None:
            user = {**user, "email": self.user.email}
        if self.user.phone_number is not None:
            user = {**user, "phoneNumber": self.user.phone_number}
        return {
            "status": self.status,
            "createdNewUser": self.created_new_user,
            "user": user,
        }


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
            raise ValueError("Third Party Info cannot be None")

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


class APIInterface(ABC):
    def __init__(self):
        self.disable_thirdparty_sign_in_up_post = False
        self.disable_authorisation_url_get = False
        self.disable_apple_redirect_handler_post = False
        self.disable_create_code_post = False
        self.disable_resend_code_post = False
        self.disable_consume_code_post = False
        self.disable_passwordless_user_email_exists_get = False
        self.disable_passwordless_user_phone_number_exists_get = False

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
    async def apple_redirect_handler_post(
        self,
        code: str,
        state: str,
        api_options: ThirdPartyAPIOptions,
        user_context: Dict[str, Any],
    ):
        pass

    @abstractmethod
    async def create_code_post(
        self,
        email: Union[str, None],
        phone_number: Union[str, None],
        api_options: PasswordlessAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[CreateCodePostOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def resend_code_post(
        self,
        device_id: str,
        pre_auth_session_id: str,
        api_options: PasswordlessAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        ResendCodePostOkResult, ResendCodePostRestartFlowError, GeneralErrorResponse
    ]:
        pass

    @abstractmethod
    async def consume_code_post(
        self,
        pre_auth_session_id: str,
        user_input_code: Union[str, None],
        device_id: Union[str, None],
        link_code: Union[str, None],
        api_options: PasswordlessAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        ConsumeCodePostOkResult,
        ConsumeCodePostRestartFlowError,
        GeneralErrorResponse,
        ConsumeCodePostIncorrectUserInputCodeError,
        ConsumeCodePostExpiredUserInputCodeError,
    ]:
        pass

    @abstractmethod
    async def passwordless_user_email_exists_get(
        self,
        email: str,
        api_options: PasswordlessAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[PasswordlessEmailExistsGetOkResult, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def passwordless_user_phone_number_exists_get(
        self,
        phone_number: str,
        api_options: PasswordlessAPIOptions,
        user_context: Dict[str, Any],
    ) -> Union[PasswordlessPhoneNumberExistsGetOkResult, GeneralErrorResponse]:
        pass
