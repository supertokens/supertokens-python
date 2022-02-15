from ...recipe_module import RecipeModule
from .recipe import PasswordlessRecipe as PasswordlessRecipe
from .utils import ContactConfig as ContactConfig, ContactEmailOnlyConfig as ContactEmailOnlyConfig, ContactEmailOrPhoneConfig as ContactEmailOrPhoneConfig, ContactPhoneOnlyConfig as ContactPhoneOnlyConfig, CreateAndSendCustomEmailParameters as CreateAndSendCustomEmailParameters, CreateAndSendCustomTextMessageParameters as CreateAndSendCustomTextMessageParameters, OverrideConfig as InputOverrideConfig, PhoneOrEmailInput as PhoneOrEmailInput
from supertokens_python.supertokens import AppInfo as AppInfo
from typing import Any, Awaitable, Callable, Dict, Union
from typing_extensions import Literal

def init(contact_config: ContactConfig, flow_type: Literal['USER_INPUT_CODE', 'MAGIC_LINK', 'USER_INPUT_CODE_AND_MAGIC_LINK'], override: Union[InputOverrideConfig, None] = ..., get_link_domain_and_path: Union[Callable[[PhoneOrEmailInput, Dict[str, Any]], Awaitable[str]], None] = ..., get_custom_user_input_code: Union[Callable[[Dict[str, Any]], Awaitable[str]], None] = ...) -> Callable[[AppInfo], RecipeModule]: ...
