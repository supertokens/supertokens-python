
# from abc import ABC, abstractmethod
# from typing import (Any, Callable, Dict, Generic, Optional, TypedDict, TypeVar,
#                     Union)

# _T = TypeVar('_T')

# from ..types import EmailDeliveryInterface

# AuthCredentials = TypedDict('auth', {'user': str,'password': str})

# SMTPServiceConfig = TypedDict('SMTPServiceConfig', {
#     'host': str,
#     'from': TypedDict('from', {'name': str, 'email': str}),
#     'port': int,
#     'secure': Union[bool, None],
#     'auth': Union[AuthCredentials, None],
# })

# class SMTPServiceConfigFrom:
#     name: str
#     email: str


# class SMTPServiceConfigAuth:
#     user: str
#     password: str

# class SMTPServiceConfig:
#     host: str
#     c_from: SMTPServiceConfigFrom
#     port: int
#     secure: Optional[bool]
#     auth: SMTPServiceConfigAuth

# class GetContentResult(TypedDict):
#     body: str
#     subject: str
#     toEmail: str

# class TypeInputSendRawEmailFrom(GetContentResult):
#     user_context: Dict[str, Any]
#     c_from: TypedDict('from', {'name': str, 'email': str})

# TypeInputSendRawEmailFrom = TypedDict('TypeInputSendRawEmailFrom', {
#     'from':
# })

# TypeInputSendRawEmail: Union[GetContentResult, Dict[str, Any], TypeInputSendRawEmailFrom]

# class ServiceInterface(ABC, Generic[_T]):
#     @abstractmethod
#     def send_raw_email(self, input: TypeInputSendRawEmail):
#         pass

#     @abstractmethod
#     def get_content(self, input: Union[_T, Any]):
#         pass

# class TypeInput(Generic[_T]):
#     smtpSettings: SMTPServiceConfig

#     @abstractmethod
#     def override(self, original_impl: ServiceInterface[_T]) -> ServiceInterface[_T]:
#         pass

# class Transporter():
#     pass

# def createTransport():
#     pass


# TypeGetDefaultEmailServiceImpl = Callable[[Transporter, TypeInputSendRawEmailFrom], ServiceInterface[_T]]


# def getEmailServiceImplementation(
#     config: TypeInput[_T],
#     getDefaultEmailServiceImplementation: TypeGetDefaultEmailServiceImpl[_T]
# ) -> EmailDeliveryInterface[_T]:
#     transporter = createTransport({'host': ...})


#     return getDefaultEmailServiceImplementation(transporter, config.smtpSettings.c_from)
