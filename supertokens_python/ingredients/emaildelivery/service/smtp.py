
from ..types import EmailDeliveryInterface
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Generic, TypedDict, TypeVar, Union

_T = TypeVar('_T')


SmtpAuth = TypedDict('auth', {'user': str, 'password': str})

SMTPServiceConfig = TypedDict('SMTPServiceConfig', {
    'host': str,
    'from': TypedDict('from', {'name': str, 'email': str}),
    'port': int,
    'secure': Union[bool, None],
    'auth': Union[SmtpAuth, None],
})

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

class GetContentResult(TypedDict):
    body: str
    subject: str
    toEmail: str

# class TypeInputSendRawEmailFrom(GetContentResult):
#     user_context: Dict[str, Any]
#     c_from: TypedDict('from', {'name': str, 'email': str})

# TypeInputSendRawEmailFrom = TypedDict('TypeInputSendRawEmailFrom', {
#     'from': TypedDict('from', {
#         'name': str,
#         'email': str
#     })
# })


class TypeInputSendRawEmailFrom:
    name: str
    email: str

    def __init__(self, name: str, email: str) -> None:
        self.name = name
        self.email = email


class TypeInputSendRawEmail(GetContentResult):
    user_context: Dict[str, Any]
    config_from: TypeInputSendRawEmailFrom

# TypeInputSendRawEmail: Union[GetContentResult, Dict[str, Any], TypeInputSendRawEmailFrom]


class TypeGetContentInput(Generic[_T]):
    user_context: Dict[str, Any]


class ServiceInterface(ABC, Generic[_T]):
    @abstractmethod
    def send_raw_email(self, input: TypeInputSendRawEmail):
        pass

    @abstractmethod
    def get_content(self, input: TypeGetContentInput[_T]):
        pass


class TypeInput(Generic[_T]):
    smtpSettings: SMTPServiceConfig

    @abstractmethod
    def override(self, oi: ServiceInterface[_T]) -> ServiceInterface[_T]:
        pass


class Transporter():
    pass


def createTransport(_) -> Transporter:
    return Transporter()


TypeGetDefaultEmailServiceImpl = Callable[[Transporter, TypeInputSendRawEmailFrom], ServiceInterface[_T]]


def getEmailServiceImplementation(
    config: TypeInput[_T],
    getDefaultEmailServiceImplementation: TypeGetDefaultEmailServiceImpl[_T]
) -> EmailDeliveryInterface[_T]:
    transporter = createTransport({'host': ...})

    config_from = config.smtpSettings['from']
    input_send_raw_email = TypeInputSendRawEmailFrom(name=config_from['name'], email=config_from['email'])
    default_impl = getDefaultEmailServiceImplementation(transporter, input_send_raw_email)
    # impl = config.override if config.override is not None else default_impl

    return default_impl
