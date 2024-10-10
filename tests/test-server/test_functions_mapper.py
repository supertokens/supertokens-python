from typing import Callable, List, Union
from typing import Dict, Any, Optional
from supertokens_python.asyncio import list_users_by_account_info
from supertokens_python.recipe.accountlinking import (
    RecipeLevelUser,
    ShouldAutomaticallyLink,
    ShouldNotAutomaticallyLink,
)
from supertokens_python.recipe.thirdparty.types import (
    RawUserInfoFromProvider,
    UserInfo,
    UserInfoEmail,
)
from supertokens_python.types import AccountInfo, RecipeUserId
from supertokens_python.types import APIResponse, User


class Info:
    core_call_count = 0


def get_func(eval_str: str) -> Callable[..., Any]:
    if eval_str.startswith("supertokens.init.supertokens.networkInterceptor"):

        def func(*args):  # type: ignore
            Info.core_call_count += 1
            return args  # type: ignore

        return func  # type: ignore

    elif eval_str.startswith("accountlinking.init.shouldDoAutomaticAccountLinking"):

        async def func(
            i: Any, l: Any, o: Any, u: Any, a: Any  # pylint: disable=unused-argument
        ) -> Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink]:
            if (
                "()=>({shouldAutomaticallyLink:!0,shouldRequireVerification:!1})"
                in eval_str
            ):
                return ShouldAutomaticallyLink(should_require_verification=False)

            if (
                "(i,l,o,u,a)=>a.DO_LINK?{shouldAutomaticallyLink:!0,shouldRequireVerification:!0}:{shouldAutomaticallyLink:!1}"
                in eval_str
            ):
                if a.get("DO_LINK"):
                    return ShouldAutomaticallyLink(should_require_verification=True)
                return ShouldNotAutomaticallyLink()

            if (
                "(i,l,o,u,a)=>a.DO_NOT_LINK?{shouldAutomaticallyLink:!1}:{shouldAutomaticallyLink:!0,shouldRequireVerification:!1}"
                in eval_str
            ):
                if a.get("DO_NOT_LINK"):
                    return ShouldNotAutomaticallyLink()
                return ShouldAutomaticallyLink(should_require_verification=False)

            if (
                "(i,l,o,u,a)=>a.DO_NOT_LINK?{shouldAutomaticallyLink:!1}:a.DO_LINK_WITHOUT_VERIFICATION?{shouldAutomaticallyLink:!0,shouldRequireVerification:!1}:{shouldAutomaticallyLink:!0,shouldRequireVerification:!0}"
                in eval_str
            ):
                if a.get("DO_NOT_LINK"):
                    return ShouldNotAutomaticallyLink()
                if a.get("DO_LINK_WITHOUT_VERIFICATION"):
                    return ShouldAutomaticallyLink(should_require_verification=False)
                return ShouldAutomaticallyLink(should_require_verification=True)

            if (
                '(i,l,o,a,e)=>e.DO_NOT_LINK||"test2@example.com"===i.email&&void 0===l?{shouldAutomaticallyLink:!1}:{shouldAutomaticallyLink:!0,shouldRequireVerification:!1}'
                in eval_str
            ):
                if a.get("DO_NOT_LINK"):
                    return ShouldNotAutomaticallyLink()
                if i.get("email") == "test2@example.com" and l is None:
                    return ShouldNotAutomaticallyLink()
                return ShouldAutomaticallyLink(should_require_verification=False)

            if (
                "(i,l,o,d,t)=>t.DO_NOT_LINK||void 0!==l&&l.id===o.getUserId()?{shouldAutomaticallyLink:!1}:{shouldAutomaticallyLink:!0,shouldRequireVerification:!1}"
                in eval_str
            ):
                if a.get("DO_NOT_LINK"):
                    return ShouldNotAutomaticallyLink()
                if l is not None and l.get("id") == o.getUserId():
                    return ShouldNotAutomaticallyLink()
                return ShouldAutomaticallyLink(should_require_verification=False)

            if (
                "(i,l,o,d,t)=>t.DO_NOT_LINK||void 0!==l&&l.id===o.getUserId()?{shouldAutomaticallyLink:!1}:{shouldAutomaticallyLink:!0,shouldRequireVerification:!0}"
                in eval_str
            ):
                if a.get("DO_NOT_LINK"):
                    return ShouldNotAutomaticallyLink()
                if l is not None and l.get("id") == o.getUserId():
                    return ShouldNotAutomaticallyLink()
                return ShouldAutomaticallyLink(should_require_verification=True)

            if (
                '(i,l,o,a,e)=>e.DO_NOT_LINK||"test2@example.com"===i.email&&void 0===l?{shouldAutomaticallyLink:!1}:{shouldAutomaticallyLink:!0,shouldRequireVerification:!0}'
                in eval_str
            ):
                if a.get("DO_NOT_LINK"):
                    return ShouldNotAutomaticallyLink()
                if i.get("email") == "test2@example.com" and l is None:
                    return ShouldNotAutomaticallyLink()
                return ShouldAutomaticallyLink(should_require_verification=True)

            if (
                'async(i,e)=>{if("emailpassword"===i.recipeId){if(!((await supertokens.listUsersByAccountInfo("public",{email:i.email})).length>1))return{shouldAutomaticallyLink:!1}}return{shouldAutomaticallyLink:!0,shouldRequireVerification:!0}}'
                in eval_str
            ):
                if i.get("recipeId") == "emailpassword":
                    users = await list_users_by_account_info(
                        "public", AccountInfo(email=i.get("email"))
                    )
                    if len(users) <= 1:
                        return ShouldNotAutomaticallyLink()
                return ShouldAutomaticallyLink(should_require_verification=True)

            if (
                "async()=>({shouldAutomaticallyLink:!0,shouldRequireVerification:!0})"
                in eval_str
                or "()=>({shouldAutomaticallyLink:!0,shouldRequireVerification:!0})"
                in eval_str
            ):
                return ShouldAutomaticallyLink(should_require_verification=True)

            return ShouldNotAutomaticallyLink()

        return func

    if eval_str.startswith("thirdparty.init.signInAndUpFeature.providers"):

        def custom_provider(provider: Any):
            if "custom-ev" in eval_str:

                def exchange_auth_code_for_oauth_tokens1(
                    redirect_uri_info: Any,  # pylint: disable=unused-argument
                    user_context: Any,  # pylint: disable=unused-argument
                ) -> Any:
                    return {}

                def get_user_info1(
                    oauth_tokens: Any,
                    user_context: Any,  # pylint: disable=unused-argument
                ):  # pylint: disable=unused-argument
                    return UserInfo(
                        third_party_user_id=oauth_tokens.get("userId", "user"),
                        email=UserInfoEmail(
                            email=oauth_tokens.get("email", "email@test.com"),
                            is_verified=True,
                        ),
                        raw_user_info_from_provider=RawUserInfoFromProvider(
                            from_id_token_payload=None,
                            from_user_info_api=None,
                        ),
                    )

                provider.exchange_auth_code_for_oauth_tokens = (
                    exchange_auth_code_for_oauth_tokens1
                )
                provider.get_user_info = get_user_info1
                return provider

            if "custom-no-ev" in eval_str:

                def exchange_auth_code_for_oauth_tokens2(
                    redirect_uri_info: Any,  # pylint: disable=unused-argument
                    user_context: Any,  # pylint: disable=unused-argument
                ) -> Any:
                    return {}

                def get_user_info2(
                    oauth_tokens: Any, user_context: Any
                ):  # pylint: disable=unused-argument
                    return UserInfo(
                        third_party_user_id=oauth_tokens.get("userId", "user"),
                        email=UserInfoEmail(
                            email=oauth_tokens.get("email", "email@test.com"),
                            is_verified=False,
                        ),
                        raw_user_info_from_provider=RawUserInfoFromProvider(
                            from_id_token_payload=None,
                            from_user_info_api=None,
                        ),
                    )

                provider.exchange_auth_code_for_oauth_tokens = (
                    exchange_auth_code_for_oauth_tokens2
                )
                provider.get_user_info = get_user_info2
                return provider

            if "custom2" in eval_str:

                def exchange_auth_code_for_oauth_tokens3(
                    redirect_uri_info: Any,
                    user_context: Any,  # pylint: disable=unused-argument
                ) -> Any:
                    return redirect_uri_info["redirectURIQueryParams"]

                def get_user_info3(
                    oauth_tokens: Any, user_context: Any
                ):  # pylint: disable=unused-argument
                    return UserInfo(
                        third_party_user_id=f"custom2{oauth_tokens['email']}",
                        email=UserInfoEmail(
                            email=oauth_tokens["email"],
                            is_verified=True,
                        ),
                        raw_user_info_from_provider=RawUserInfoFromProvider(
                            from_id_token_payload=None,
                            from_user_info_api=None,
                        ),
                    )

                provider.exchange_auth_code_for_oauth_tokens = (
                    exchange_auth_code_for_oauth_tokens3
                )
                provider.get_user_info = get_user_info3
                return provider

            if "custom3" in eval_str:

                def exchange_auth_code_for_oauth_tokens4(
                    redirect_uri_info: Any,
                    user_context: Any,  # pylint: disable=unused-argument
                ) -> Any:
                    return redirect_uri_info["redirectURIQueryParams"]

                def get_user_info4(
                    oauth_tokens: Any, user_context: Any
                ):  # pylint: disable=unused-argument
                    return UserInfo(
                        third_party_user_id=oauth_tokens["email"],
                        email=UserInfoEmail(
                            email=oauth_tokens["email"],
                            is_verified=True,
                        ),
                        raw_user_info_from_provider=RawUserInfoFromProvider(
                            from_id_token_payload=None,
                            from_user_info_api=None,
                        ),
                    )

                provider.exchange_auth_code_for_oauth_tokens = (
                    exchange_auth_code_for_oauth_tokens4
                )
                provider.get_user_info = get_user_info4
                return provider

            if "custom" in eval_str:

                def exchange_auth_code_for_oauth_tokens5(
                    redirect_uri_info: Any,
                    user_context: Any,  # pylint: disable=unused-argument
                ) -> Any:
                    return redirect_uri_info

                def get_user_info5(
                    oauth_tokens: Any, user_context: Any
                ):  # pylint: disable=unused-argument
                    if oauth_tokens.get("error"):
                        raise Exception("Credentials error")
                    return UserInfo(
                        third_party_user_id=oauth_tokens.get("userId", "userId"),
                        email=(
                            None
                            if oauth_tokens.get("email") is None
                            else UserInfoEmail(
                                email=oauth_tokens.get("email"),
                                is_verified=oauth_tokens.get("isVerified", False),
                            )
                        ),
                        raw_user_info_from_provider=RawUserInfoFromProvider(
                            from_id_token_payload=None,
                            from_user_info_api=None,
                        ),
                    )

                provider.exchange_auth_code_for_oauth_tokens = (
                    exchange_auth_code_for_oauth_tokens5
                )
                provider.get_user_info = get_user_info5
                return provider

        return custom_provider

    raise Exception("Unknown eval string: " + eval_str)


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
