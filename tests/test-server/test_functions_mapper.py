from typing import Callable, List
from typing import Dict, Any, Optional
from supertokens_python.recipe.accountlinking import RecipeLevelUser
from supertokens_python.types import RecipeUserId
from supertokens_python.types import APIResponse, User


class Info:
    core_call_count = 0


def get_func(eval_str: str) -> Callable:  # type: ignore
    if eval_str.startswith("supertokens.init.supertokens.networkInterceptor"):

        def func(*args):  # type: ignore
            Info.core_call_count += 1
            return args  # type: ignore

        return func  # type: ignore

    raise Exception("Unknown eval string")


class OverrideParams(APIResponse):
    def __init__(
        self,
        send_email_to_user_id: Optional[str] = None,
        token: Optional[str] = None,
        user_post_password_reset: Optional[User] = None,
        email_post_password_reset: Optional[str] = None,
        send_email_callback_called: Optional[bool] = None,
        send_email_to_user_email: Optional[str] = None,
        send_email_inputs: Optional[List[str]] = None,
        send_sms_inputs: Optional[List[str]] = None,
        send_email_to_recipe_user_id: Optional[str] = None,
        user_in_callback: Optional[User] = None,
        email: Optional[str] = None,
        new_account_info_in_callback: Optional[RecipeLevelUser] = None,
        primary_user_in_callback: Optional[User] = None,
        user_id_in_callback: Optional[str] = None,
        recipe_user_id_in_callback: Optional[str] = None,
        core_call_count: int = 0,
        store: Optional[Any] = None,
    ):
        self.send_email_to_user_id = send_email_to_user_id
        self.token = token
        self.user_post_password_reset = user_post_password_reset
        self.email_post_password_reset = email_post_password_reset
        self.send_email_callback_called = send_email_callback_called
        self.send_email_to_user_email = send_email_to_user_email
        self.send_email_inputs = send_email_inputs
        self.send_sms_inputs = send_sms_inputs
        self.send_email_to_recipe_user_id = send_email_to_recipe_user_id
        self.user_in_callback = user_in_callback
        self.email = email
        self.new_account_info_in_callback = new_account_info_in_callback
        self.primary_user_in_callback = primary_user_in_callback
        self.user_id_in_callback = user_id_in_callback
        self.recipe_user_id_in_callback = recipe_user_id_in_callback
        self.core_call_count = core_call_count
        self.store = store

    def to_json(self) -> Dict[str, Any]:
        return {
            "sendEmailToUserId": self.send_email_to_user_id,
            "token": self.token,
            "userPostPasswordReset": (
                self.user_post_password_reset.to_json()
                if self.user_post_password_reset is not None
                else None
            ),
            "emailPostPasswordReset": self.email_post_password_reset,
            "sendEmailCallbackCalled": self.send_email_callback_called,
            "sendEmailToUserEmail": self.send_email_to_user_email,
            "sendEmailInputs": self.send_email_inputs,
            "sendSmsInputs": self.send_sms_inputs,
            "sendEmailToRecipeUserId": self.send_email_to_recipe_user_id,
            "userInCallback": (
                self.user_in_callback.to_json()
                if self.user_in_callback is not None
                else None
            ),
            "email": self.email,
            "newAccountInfoInCallback": self.new_account_info_in_callback,
            "primaryUserInCallback": (
                self.primary_user_in_callback.to_json()
                if self.primary_user_in_callback is not None
                else None
            ),
            "userIdInCallback": self.user_id_in_callback,
            "recipeUserIdInCallback": self.recipe_user_id_in_callback,
            "info": {
                "coreCallCount": self.core_call_count,
            },
            "store": self.store,
        }


def get_override_params() -> OverrideParams:
    return OverrideParams(
        send_email_to_user_id=send_email_to_user_id,
        token=token,
        user_post_password_reset=user_post_password_reset,
        email_post_password_reset=email_post_password_reset,
        send_email_callback_called=send_email_callback_called,
        send_email_to_user_email=send_email_to_user_email,
        send_email_inputs=send_email_inputs,
        send_sms_inputs=send_sms_inputs,
        send_email_to_recipe_user_id=send_email_to_recipe_user_id,
        user_in_callback=user_in_callback,
        email=email,
        new_account_info_in_callback=new_account_info_in_callback,
        primary_user_in_callback=(
            primary_user_in_callback if primary_user_in_callback else None
        ),
        user_id_in_callback=user_id_in_callback,
        recipe_user_id_in_callback=(
            recipe_user_id_in_callback.get_as_string()
            if isinstance(recipe_user_id_in_callback, RecipeUserId)
            else None
        ),
        core_call_count=Info.core_call_count,
        store=store,
    )


def reset_override_params():
    global send_email_to_user_id, token, user_post_password_reset, email_post_password_reset, send_email_callback_called, send_email_to_user_email, send_email_inputs, send_sms_inputs, send_email_to_recipe_user_id, user_in_callback, email, primary_user_in_callback, new_account_info_in_callback, user_id_in_callback, recipe_user_id_in_callback, store
    send_email_to_user_id = None
    token = None
    user_post_password_reset = None
    email_post_password_reset = None
    send_email_callback_called = False
    send_email_to_user_email = None
    send_email_inputs = []
    send_sms_inputs = []
    send_email_to_recipe_user_id = None
    user_in_callback = None
    email = None
    primary_user_in_callback = None
    new_account_info_in_callback = None
    user_id_in_callback = None
    recipe_user_id_in_callback = None
    store = None
    Info.core_call_count = 0


send_email_to_user_id: Optional[str] = None
token: Optional[str] = None
user_post_password_reset: Optional[User] = None
email_post_password_reset: Optional[str] = None
send_email_callback_called: bool = False
send_email_to_user_email: Optional[str] = None
send_email_inputs: List[str] = []
send_sms_inputs: List[str] = []
send_email_to_recipe_user_id: Optional[str] = None
user_in_callback: Optional[User] = None
email: Optional[str] = None
primary_user_in_callback: Optional[User] = None
new_account_info_in_callback: Optional[RecipeLevelUser] = None
user_id_in_callback: Optional[str] = None
recipe_user_id_in_callback: Optional[RecipeUserId] = None
store: Optional[str] = None
