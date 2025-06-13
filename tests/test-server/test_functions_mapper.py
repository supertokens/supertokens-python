from typing import Any, Callable, Dict, List, Optional, Union

from supertokens_python.asyncio import list_users_by_account_info
from supertokens_python.recipe.accountlinking import (
    RecipeLevelUser,
    ShouldAutomaticallyLink,
    ShouldNotAutomaticallyLink,
)
from supertokens_python.recipe.dashboard.interfaces import APIOptions
from supertokens_python.recipe.emailpassword.interfaces import (
    EmailAlreadyExistsError,
    PasswordPolicyViolationError,
    PasswordResetPostOkResult,
    PasswordResetTokenInvalidError,
    SignUpPostNotAllowedResponse,
    SignUpPostOkResult,
)
from supertokens_python.recipe.emailpassword.types import (
    EmailDeliveryOverrideInput,
    EmailTemplateVars,
    FormField,
)
from supertokens_python.recipe.emailverification.interfaces import (
    EmailDoesNotExistError,
    GetEmailForUserIdOkResult,
)
from supertokens_python.recipe.emailverification.types import (
    VerificationEmailTemplateVarsUser,
)
from supertokens_python.recipe.multifactorauth.interfaces import (
    ResyncSessionAndFetchMFAInfoPUTOkResult,
)
from supertokens_python.recipe.multifactorauth.types import MFARequirementList
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.claims import PrimitiveClaim
from supertokens_python.recipe.thirdparty.interfaces import (
    SignInUpNotAllowed,
    SignInUpOkResult,
    SignInUpPostNoEmailGivenByProviderResponse,
    SignInUpPostOkResult,
)
from supertokens_python.recipe.thirdparty.provider import Provider, RedirectUriInfo
from supertokens_python.recipe.thirdparty.types import (
    RawUserInfoFromProvider,
    UserInfo,
    UserInfoEmail,
)
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError
from supertokens_python.types.base import AccountInfoInput
from supertokens_python.types.response import APIResponse, GeneralErrorResponse


class Info:
    core_call_count = 0


def get_func(eval_str: str) -> Callable[..., Any]:
    global store  # pylint: disable=global-variable-not-assigned
    global send_email_inputs  # pylint: disable=global-variable-not-assigned
    global send_sms_inputs  # pylint: disable=global-variable-not-assigned
    if eval_str.startswith("supertokens.init.supertokens.networkInterceptor"):

        def func(*args):  # type: ignore
            Info.core_call_count += 1
            return args  # type: ignore

        return func  # type: ignore

    elif eval_str.startswith("accountlinking.init.onAccountLinked"):

        async def on_account_linked(
            user: User, recipe_level_user: RecipeLevelUser, user_context: Dict[str, Any]
        ) -> None:
            global primary_user_in_callback
            global new_account_info_in_callback
            primary_user_in_callback = user
            new_account_info_in_callback = recipe_level_user

        return on_account_linked

    elif eval_str.startswith("multifactorauth.init.override.apis"):
        from supertokens_python.recipe.multifactorauth.interfaces import (
            APIInterface as MFAAPIInterface,
        )
        from supertokens_python.recipe.multifactorauth.interfaces import (
            APIOptions as MFAAPIOptions,
        )

        def mfa_override_apis(
            original_implementation: MFAAPIInterface,
        ) -> MFAAPIInterface:
            original_resync_session_and_fetch_mfa_info_put = (
                original_implementation.resync_session_and_fetch_mfa_info_put
            )

            async def resync_session_and_fetch_mfa_info_put(
                api_options: MFAAPIOptions,
                session: SessionContainer,
                user_context: Dict[str, Any],
            ) -> Union[ResyncSessionAndFetchMFAInfoPUTOkResult, GeneralErrorResponse]:
                json_body = await api_options.request.json()
                if (
                    json_body is not None
                    and json_body.get("userContext", {}).get("requireFactor")
                    is not None
                ):
                    user_context["requireFactor"] = json_body["userContext"][
                        "requireFactor"
                    ]

                return await original_resync_session_and_fetch_mfa_info_put(
                    api_options, session, user_context
                )

            original_implementation.resync_session_and_fetch_mfa_info_put = (
                resync_session_and_fetch_mfa_info_put
            )
            return original_implementation

        return mfa_override_apis

    elif eval_str.startswith("multifactorauth.init.override.functions"):
        from supertokens_python.recipe.multifactorauth.interfaces import (
            RecipeInterface as MFARecipeInterface,
        )

        def mfa_override_functions(
            original_implementation: MFARecipeInterface,
        ) -> MFARecipeInterface:
            async def get_mfa_requirements_for_auth(
                tenant_id: str,
                access_token_payload: Dict[str, Any],
                completed_factors: Dict[str, int],
                user: Any,
                factors_set_up_for_user: Any,
                required_secondary_factors_for_user: Any,
                required_secondary_factors_for_tenant: Any,
                user_context: Dict[str, Any],
            ) -> MFARequirementList:
                # Test specifies an override, return the required data
                if 'getMFARequirementsForAuth:async()=>["totp"]' in eval_str:
                    return ["totp"]

                return ["otp-phone"] if user_context.get("requireFactor") else []

            original_implementation.get_mfa_requirements_for_auth = (
                get_mfa_requirements_for_auth
            )
            return original_implementation

        return mfa_override_functions

    elif eval_str.startswith("emailverification.init.emailDelivery.override"):
        from supertokens_python.recipe.emailverification.types import (
            EmailDeliveryOverrideInput as EVEmailDeliveryOverrideInput,
        )
        from supertokens_python.recipe.emailverification.types import (
            EmailTemplateVars as EVEmailTemplateVars,
        )

        def custom_email_delivery_override(
            original_implementation: EVEmailDeliveryOverrideInput,
        ) -> EVEmailDeliveryOverrideInput:
            original_send_email = original_implementation.send_email

            async def send_email(
                template_vars: EVEmailTemplateVars, user_context: Dict[str, Any]
            ) -> None:
                global user_in_callback  # pylint: disable=global-variable-not-assigned
                global token  # pylint: disable=global-variable-not-assigned

                if template_vars.user:
                    user_in_callback = template_vars.user

                if template_vars.email_verify_link:
                    token = template_vars.email_verify_link.split("?token=")[1].split(
                        "&tenantId="
                    )[0]

                # Call the original implementation
                await original_send_email(template_vars, user_context)

            original_implementation.send_email = send_email
            return original_implementation

        return custom_email_delivery_override

    elif eval_str.startswith("session.override.functions"):
        from supertokens_python.recipe.session.interfaces import (
            RecipeInterface as SessionRecipeInterface,
        )

        def session_override_functions(
            original_implementation: SessionRecipeInterface,
        ) -> SessionRecipeInterface:
            original_create_new_session = original_implementation.create_new_session

            async def create_new_session(
                user_id: str,
                recipe_user_id: RecipeUserId,
                access_token_payload: Optional[Dict[str, Any]],
                session_data_in_database: Optional[Dict[str, Any]],
                disable_anti_csrf: Optional[bool],
                tenant_id: str,
                user_context: Dict[str, Any],
            ) -> SessionContainer:
                async def fetch_value(
                    _user_id: str,
                    recipe_user_id: RecipeUserId,
                    tenant_id: str,
                    current_payload: Dict[str, Any],
                    user_context: Dict[str, Any],
                ) -> None:
                    global user_id_in_callback
                    global recipe_user_id_in_callback
                    user_id_in_callback = user_id
                    recipe_user_id_in_callback = recipe_user_id
                    return None

                claim = PrimitiveClaim[Any](key="some-key", fetch_value=fetch_value)

                if access_token_payload is None:
                    access_token_payload = {}
                json_update = await claim.build(
                    user_id,
                    recipe_user_id,
                    tenant_id,
                    access_token_payload,
                    user_context,
                )
                access_token_payload.update(json_update)

                return await original_create_new_session(
                    user_id,
                    recipe_user_id,
                    access_token_payload,
                    session_data_in_database,
                    disable_anti_csrf,
                    tenant_id,
                    user_context,
                )

            original_implementation.create_new_session = create_new_session
            return original_implementation

        return session_override_functions

    elif eval_str.startswith("emailpassword.init.emailDelivery.override"):

        def custom_email_deliver(
            original_implementation: EmailDeliveryOverrideInput,
        ) -> EmailDeliveryOverrideInput:
            original_send_email = original_implementation.send_email

            async def send_email(
                template_vars: EmailTemplateVars, user_context: Dict[str, Any]
            ) -> None:
                global send_email_callback_called  # pylint: disable=global-variable-not-assigned
                global send_email_to_user_id  # pylint: disable=global-variable-not-assigned
                global send_email_to_user_email  # pylint: disable=global-variable-not-assigned
                global send_email_to_recipe_user_id  # pylint: disable=global-variable-not-assigned
                global token  # pylint: disable=global-variable-not-assigned
                send_email_callback_called = True

                if template_vars.user:
                    send_email_to_user_id = template_vars.user.id

                    if template_vars.user.email:
                        send_email_to_user_email = template_vars.user.email

                    if template_vars.user.recipe_user_id:
                        send_email_to_recipe_user_id = (
                            template_vars.user.recipe_user_id.get_as_string()
                        )

                if template_vars.password_reset_link:
                    token = (
                        template_vars.password_reset_link.split("?")[1]
                        .split("&")[0]
                        .split("=")[1]
                    )

                # Use the original implementation which calls the default service,
                # or a service that you may have specified in the email_delivery object.
                return await original_send_email(template_vars, user_context)

            original_implementation.send_email = send_email
            return original_implementation

        return custom_email_deliver
    elif eval_str.startswith("passwordless.init.emailDelivery.service.sendEmail"):

        def func1(
            template_vars: Any,
            user_context: Dict[str, Any],  # pylint: disable=unused-argument
        ) -> None:  # pylint: disable=unused-argument
            # Add to store
            jsonified = {
                "codeLifeTime": template_vars.code_life_time,
                "email": template_vars.email,
                "isFirstFactor": template_vars.is_first_factor,
                "preAuthSessionId": template_vars.pre_auth_session_id,
                "tenantId": template_vars.tenant_id,
                "urlWithLinkCode": template_vars.url_with_link_code,
                "userInputCode": template_vars.user_input_code,
            }
            jsonified = {k: v for k, v in jsonified.items() if v is not None}
            if "emailInputs" in store:
                store["emailInputs"].append(jsonified)  # type: ignore
            else:
                store["emailInputs"] = [jsonified]

            # Add to send_email_inputs
            send_email_inputs.append(jsonified)  # type: ignore

        return func1

    if eval_str.startswith("thirdparty.init.override.functions"):
        if "setIsVerifiedInSignInUp" in eval_str:
            from supertokens_python.recipe.thirdparty.interfaces import (
                RecipeInterface as ThirdPartyRecipeInterface,
            )

            def custom_override(
                original_implementation: ThirdPartyRecipeInterface,
            ) -> ThirdPartyRecipeInterface:
                og_sign_in_up = original_implementation.sign_in_up

                async def sign_in_up(
                    third_party_id: str,
                    third_party_user_id: str,
                    email: str,
                    is_verified: bool,
                    oauth_tokens: Dict[str, Any],
                    raw_user_info_from_provider: RawUserInfoFromProvider,
                    session: Optional[SessionContainer],
                    should_try_linking_with_session_user: Union[bool, None],
                    tenant_id: str,
                    user_context: Dict[str, Any],
                ) -> Union[
                    SignInUpOkResult,
                    SignInUpNotAllowed,
                    LinkingToSessionUserFailedError,
                ]:
                    user_context["isVerified"] = (
                        is_verified  # this information comes from the third party provider
                    )
                    return await og_sign_in_up(
                        third_party_id,
                        third_party_user_id,
                        email,
                        is_verified,
                        oauth_tokens,
                        raw_user_info_from_provider,
                        session,
                        should_try_linking_with_session_user,
                        tenant_id,
                        user_context,
                    )

                original_implementation.sign_in_up = sign_in_up
                return original_implementation

            return custom_override

    elif eval_str.startswith("passwordless.init.smsDelivery.service.sendSms"):

        def func2(template_vars: Any, user_context: Dict[str, Any]) -> None:  # pylint: disable=unused-argument
            jsonified = {
                "codeLifeTime": template_vars.code_life_time,
                "phoneNumber": template_vars.phone_number,
                "isFirstFactor": template_vars.is_first_factor,
                "preAuthSessionId": template_vars.pre_auth_session_id,
                "tenantId": template_vars.tenant_id,
                "urlWithLinkCode": template_vars.url_with_link_code,
                "userInputCode": template_vars.user_input_code,
            }
            jsonified = {k: v for k, v in jsonified.items() if v is not None}
            send_sms_inputs.append(jsonified)  # type: ignore

        return func2

    elif eval_str.startswith("passwordless.init.override.apis"):

        def func3(oI: Any) -> Dict[str, Any]:
            og = oI.consume_code_post

            async def consume_code_post(
                pre_auth_session_id: str,
                user_input_code: Union[str, None],
                device_id: Union[str, None],
                link_code: Union[str, None],
                session: Optional[SessionContainer],
                should_try_linking_with_session_user: Union[bool, None],
                tenant_id: str,
                api_options: APIOptions,
                user_context: Dict[str, Any],
            ) -> Any:
                o = await api_options.request.json()
                assert o is not None
                if o.get("userContext", {}).get("DO_LINK") is not None:
                    user_context["DO_LINK"] = o["userContext"]["DO_LINK"]
                return await og(
                    pre_auth_session_id,
                    user_input_code,
                    device_id,
                    link_code,
                    session,
                    should_try_linking_with_session_user,
                    tenant_id,
                    api_options,
                    user_context,
                )

            oI.consume_code_post = consume_code_post
            return oI

        return func3

    elif eval_str.startswith("emailpassword.init.override.apis"):
        from supertokens_python.recipe.emailpassword.interfaces import (
            APIInterface as EmailPasswordAPIInterface,
        )
        from supertokens_python.recipe.emailpassword.interfaces import (
            APIOptions as EmailPasswordAPIOptions,
        )

        def ep_override_apis(
            original_implementation: EmailPasswordAPIInterface,
        ) -> EmailPasswordAPIInterface:
            og_password_reset_post = original_implementation.password_reset_post
            og_sign_up_post = original_implementation.sign_up_post

            async def password_reset_post(
                form_fields: List[FormField],
                token: str,
                tenant_id: str,
                api_options: EmailPasswordAPIOptions,
                user_context: Dict[str, Any],
            ) -> Union[
                PasswordResetPostOkResult,
                PasswordResetTokenInvalidError,
                PasswordPolicyViolationError,
                GeneralErrorResponse,
            ]:
                if "DO_NOT_LINK" in eval_str:
                    user_context["DO_NOT_LINK"] = True
                t = await og_password_reset_post(
                    form_fields, token, tenant_id, api_options, user_context
                )
                if isinstance(t, PasswordResetPostOkResult):
                    global email_post_password_reset, user_post_password_reset
                    email_post_password_reset = t.email
                    user_post_password_reset = t.user
                return t

            async def sign_up_post(
                form_fields: List[FormField],
                tenant_id: str,
                session: Union[SessionContainer, None],
                should_try_linking_with_session_user: Union[bool, None],
                api_options: EmailPasswordAPIOptions,
                user_context: Dict[str, Any],
            ) -> Union[
                SignUpPostOkResult,
                EmailAlreadyExistsError,
                SignUpPostNotAllowedResponse,
                GeneralErrorResponse,
            ]:
                if "signUpPOST" in eval_str:
                    n = await api_options.request.json()
                    assert n is not None
                    if n.get("userContext", {}).get("DO_LINK") is not None:
                        user_context["DO_LINK"] = n["userContext"]["DO_LINK"]
                return await og_sign_up_post(
                    form_fields,
                    tenant_id,
                    session,
                    should_try_linking_with_session_user,
                    api_options,
                    user_context,
                )

            original_implementation.password_reset_post = password_reset_post
            original_implementation.sign_up_post = sign_up_post
            return original_implementation

        return ep_override_apis

    elif eval_str.startswith("emailverification.init.override.functions"):
        from supertokens_python.recipe.emailverification.interfaces import (
            RecipeInterface as EmailVerificationRecipeInterface,
        )

        def ev_override_functions(
            original_implementation: EmailVerificationRecipeInterface,
        ) -> EmailVerificationRecipeInterface:
            og_is_email_verified = original_implementation.is_email_verified

            async def is_email_verified(
                recipe_user_id: RecipeUserId, email: str, user_context: Dict[str, Any]
            ) -> bool:
                global email_param
                email_param = email
                return await og_is_email_verified(recipe_user_id, email, user_context)

            original_implementation.is_email_verified = is_email_verified
            return original_implementation

        return ev_override_functions

    elif eval_str.startswith("thirdparty.init.override.apis"):
        from supertokens_python.recipe.thirdparty.interfaces import (
            APIInterface as ThirdPartyAPIInterface,
        )
        from supertokens_python.recipe.thirdparty.interfaces import (
            APIOptions as ThirdPartyAPIOptions,
        )

        def tp_override_apis(
            original_implementation: ThirdPartyAPIInterface,
        ) -> ThirdPartyAPIInterface:
            og_sign_in_up_post = original_implementation.sign_in_up_post

            async def sign_in_up_post(
                provider: Provider,
                redirect_uri_info: Optional[RedirectUriInfo],
                oauth_tokens: Optional[Dict[str, Any]],
                session: Optional[SessionContainer],
                should_try_linking_with_session_user: Union[bool, None],
                tenant_id: str,
                api_options: ThirdPartyAPIOptions,
                user_context: Dict[str, Any],
            ) -> Union[
                SignInUpPostOkResult,
                SignInUpPostNoEmailGivenByProviderResponse,
                SignInUpNotAllowed,
                GeneralErrorResponse,
            ]:
                json_body = await api_options.request.json()
                if (
                    json_body is not None
                    and json_body.get("userContext", {}).get("DO_LINK") is not None
                ):
                    user_context["DO_LINK"] = json_body["userContext"]["DO_LINK"]

                result = await og_sign_in_up_post(
                    provider,
                    redirect_uri_info,
                    oauth_tokens,
                    session,
                    should_try_linking_with_session_user,
                    tenant_id,
                    api_options,
                    user_context,
                )

                if isinstance(result, SignInUpPostOkResult):
                    global user_in_callback
                    user_in_callback = result.user

                return result

            original_implementation.sign_in_up_post = sign_in_up_post
            return original_implementation

        return tp_override_apis

    elif eval_str.startswith("accountlinking.init.shouldDoAutomaticAccountLinking"):
        if "onlyLinkIfNewUserVerified" in eval_str:

            async def func4(
                new_user_account: Any,
                existing_user: Any,
                session: Any,
                tenant_id: Any,
                user_context: Dict[str, Any],
            ) -> Union[ShouldNotAutomaticallyLink, ShouldAutomaticallyLink]:
                if user_context.get("DO_NOT_LINK"):
                    return ShouldNotAutomaticallyLink()

                if (
                    new_user_account.third_party is not None
                    and existing_user is not None
                ):
                    if user_context.get("isVerified"):
                        return ShouldAutomaticallyLink(should_require_verification=True)
                    return ShouldNotAutomaticallyLink()

                return ShouldAutomaticallyLink(should_require_verification=True)

            return func4

        async def func(
            i: Any,
            l: Any,  # noqa: E741
            o: Any,
            u: Any,
            a: Any,  # pylint: disable=unused-argument
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
                if i.email == "test2@example.com" and l is None:
                    return ShouldNotAutomaticallyLink()
                return ShouldAutomaticallyLink(should_require_verification=False)

            if (
                "(i,l,o,d,t)=>t.DO_NOT_LINK||void 0!==l&&l.id===o.getUserId()?{shouldAutomaticallyLink:!1}:{shouldAutomaticallyLink:!0,shouldRequireVerification:!1}"
                in eval_str
            ):
                if a.get("DO_NOT_LINK"):
                    return ShouldNotAutomaticallyLink()
                if l is not None and l.id == o.get_user_id():
                    return ShouldNotAutomaticallyLink()
                return ShouldAutomaticallyLink(should_require_verification=False)

            if (
                "(i,l,o,d,t)=>t.DO_NOT_LINK||void 0!==l&&l.id===o.getUserId()?{shouldAutomaticallyLink:!1}:{shouldAutomaticallyLink:!0,shouldRequireVerification:!0}"
                in eval_str
            ):
                if a.get("DO_NOT_LINK"):
                    return ShouldNotAutomaticallyLink()
                if l is not None and l.id == o.get_user_id():
                    return ShouldNotAutomaticallyLink()
                return ShouldAutomaticallyLink(should_require_verification=True)

            if (
                '(i,l,o,a,e)=>e.DO_NOT_LINK||"test2@example.com"===i.email&&void 0===l?{shouldAutomaticallyLink:!1}:{shouldAutomaticallyLink:!0,shouldRequireVerification:!0}'
                in eval_str
            ):
                if a.get("DO_NOT_LINK"):
                    return ShouldNotAutomaticallyLink()
                if i.email == "test2@example.com" and l is None:
                    return ShouldNotAutomaticallyLink()
                return ShouldAutomaticallyLink(should_require_verification=True)

            if (
                'async(i,e)=>{if("emailpassword"===i.recipeId){if(!((await supertokens.listUsersByAccountInfo("public",{email:i.email})).length>1))return{shouldAutomaticallyLink:!1}}return{shouldAutomaticallyLink:!0,shouldRequireVerification:!0}}'
                in eval_str
            ):
                if i.recipe_id == "emailpassword":
                    users = await list_users_by_account_info(
                        "public", AccountInfoInput(email=i.email)
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

                async def exchange_auth_code_for_oauth_tokens1(
                    redirect_uri_info: RedirectUriInfo,
                    user_context: Any,  # pylint: disable=unused-argument
                ) -> Any:
                    return redirect_uri_info.redirect_uri_query_params

                async def get_user_info1(
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

                async def exchange_auth_code_for_oauth_tokens2(
                    redirect_uri_info: RedirectUriInfo,
                    user_context: Any,  # pylint: disable=unused-argument
                ) -> Any:
                    return redirect_uri_info.redirect_uri_query_params

                async def get_user_info2(oauth_tokens: Any, user_context: Any):  # pylint: disable=unused-argument
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

                async def exchange_auth_code_for_oauth_tokens3(
                    redirect_uri_info: RedirectUriInfo,
                    user_context: Any,  # pylint: disable=unused-argument
                ) -> Any:
                    return redirect_uri_info.redirect_uri_query_params

                async def get_user_info3(oauth_tokens: Any, user_context: Any):  # pylint: disable=unused-argument
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

                async def exchange_auth_code_for_oauth_tokens4(
                    redirect_uri_info: RedirectUriInfo,
                    user_context: Any,  # pylint: disable=unused-argument
                ) -> Any:
                    return redirect_uri_info.redirect_uri_query_params

                async def get_user_info4(oauth_tokens: Any, user_context: Any):  # pylint: disable=unused-argument
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

                async def exchange_auth_code_for_oauth_tokens5(
                    redirect_uri_info: RedirectUriInfo,
                    user_context: Any,  # pylint: disable=unused-argument
                ) -> Any:
                    return redirect_uri_info.redirect_uri_query_params

                async def get_user_info5(oauth_tokens: Any, user_context: Any):  # pylint: disable=unused-argument
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

    if eval_str.startswith("emailverification.init.getEmailForRecipeUserId"):
        from supertokens_python.recipe.emailverification.interfaces import (
            UnknownUserIdError as EVUnknownUserId,
        )

        async def get_email_for_recipe_user_id(
            recipe_user_id: RecipeUserId,
            user_context: Dict[str, Any],
        ) -> Union[GetEmailForUserIdOkResult, EmailDoesNotExistError, EVUnknownUserId]:
            if "random@example.com" in eval_str:
                return GetEmailForUserIdOkResult(email="random@example.com")

            if (
                hasattr(recipe_user_id, "get_as_string")
                and recipe_user_id.get_as_string() == "random"
            ):
                return GetEmailForUserIdOkResult(email="test@example.com")

            return EVUnknownUserId()

        return get_email_for_recipe_user_id

    if eval_str.startswith("webauthn.init.getOrigin"):
        if 'async()=>"https://api.supertokens.io"' in eval_str:

            async def origin_fn_1(*_: Any, **__: Any):
                return "https://api.supertokens.io"

            return origin_fn_1

        if 'async()=>"https://supertokens.io"' in eval_str:

            async def origin_fn_2(*_: Any, **__: Any):
                return "https://supertokens.io"

            return origin_fn_2

        if '()=>"https://test.testId.com"' in eval_str:

            async def origin_fn_3(*_: Any, **__: Any):
                return "https://test.testId.com"

            return origin_fn_3

        if '()=>"https://test.testOrigin.com"' in eval_str:

            async def origin_fn_4(*_: Any, **__: Any):
                return "https://test.testOrigin.com"

            return origin_fn_4

    if eval_str.startswith("webauthn.init.getRelyingPartyId"):
        if '()=>"testOrigin.com"' in eval_str:

            async def rp_id_fn_1(*_: Any, **__: Any):
                return "testOrigin.com"

            return rp_id_fn_1

        if 'async()=>"supertokens.io"' in eval_str:

            async def rp_id_fn_2(*_: Any, **__: Any):
                return "supertokens.io"

            return rp_id_fn_2

    if eval_str.startswith("webauthn.init.getRelyingPartyName"):
        if '()=>"testName"' in eval_str:

            async def rp_name_fn_1(*_: Any, **__: Any):
                return "testName"

            return rp_name_fn_1

        if '()=>"SuperTokens"' in eval_str:

            async def rp_name_fn_2(*_: Any, **__: Any):
                return "SuperTokens"

            return rp_name_fn_2

    if eval_str.startswith("webauthn.init.validateEmailAddress"):
        if 'e=>"test@example.com"===e?void 0:"Invalid email"' in eval_str:

            async def validate_email_fn_1(*, email: str, **_: Any):
                if email == "test@example.com":
                    return None
                return "Invalid email"

            return validate_email_fn_1

    if eval_str.startswith("webauthn.init.override.functions"):
        from supertokens_python.recipe.webauthn.recipe_implementation import (
            RecipeImplementation as WebauthnRecipeImplementation,
        )

        if (
            'e=>({...e,registerOptions:r=>e.registerOptions({...r,timeout:1e4,userVerification:"required",relyingPartyId:"testId.com",userPresence:!1})})'
            in eval_str
        ):

            def register_options_override_1(
                original_implementation: WebauthnRecipeImplementation,
            ) -> WebauthnRecipeImplementation:
                og_register_options = original_implementation.register_options

                async def register_options(
                    **kwargs: Dict[str, Any],
                ):
                    return await og_register_options(
                        **{
                            **kwargs,  # type: ignore
                            "relying_party_id": "testId.com",
                            "timeout": 10 * 1000,
                            "user_verification": "required",
                            "user_presence": False,
                        }
                    )

                original_implementation.register_options = register_options  # type: ignore
                return original_implementation

            return register_options_override_1

        if (
            "t=>({...t,registerOptions:async function(e){return t.registerOptions({...e,timeout:50})}})"
            in eval_str
        ):

            def register_options_override_2(
                original_implementation: WebauthnRecipeImplementation,
            ) -> WebauthnRecipeImplementation:
                og_register_options = original_implementation.register_options

                async def register_options(
                    **kwargs: Dict[str, Any],
                ):
                    return await og_register_options(
                        **{
                            **kwargs,  # type: ignore
                            "timeout": 50,
                        }
                    )

                original_implementation.register_options = register_options  # type: ignore
                return original_implementation

            return register_options_override_2

        if (
            "t=>({...t,registerOptions:async function(e){return t.registerOptions({...e,timeout:500})}})"
            in eval_str
        ):

            def register_options_override_3(
                original_implementation: WebauthnRecipeImplementation,
            ) -> WebauthnRecipeImplementation:
                og_register_options = original_implementation.register_options

                async def register_options(
                    **kwargs: Dict[str, Any],
                ):
                    return await og_register_options(
                        **{
                            **kwargs,  # type: ignore
                            "timeout": 500,
                        }
                    )

                original_implementation.register_options = register_options  # type: ignore
                return original_implementation

            return register_options_override_3

        if (
            "n=>({...n,signInOptions:async function(i){return n.signInOptions({...i,timeout:500})}})"
            in eval_str
        ):

            def sign_in_options_override_1(
                original_implementation: WebauthnRecipeImplementation,
            ) -> WebauthnRecipeImplementation:
                og_sign_in_options = original_implementation.sign_in_options

                async def sign_in_options(
                    **kwargs: Dict[str, Any],
                ):
                    return await og_sign_in_options(
                        **{
                            **kwargs,  # type: ignore
                            "timeout": 500,
                        }
                    )

                original_implementation.sign_in_options = sign_in_options  # type: ignore
                return original_implementation

            return sign_in_options_override_1

    # if eval_str.startswith("webauthn.init.override.apis"):
    #     pass

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
        send_sms_inputs: List[str] = [],  # pylint: disable=dangerous-default-value
        send_email_to_recipe_user_id: Optional[str] = None,
        user_in_callback: Optional[
            Union[User, VerificationEmailTemplateVarsUser]
        ] = None,
        email: Optional[str] = None,
        new_account_info_in_callback: Optional[RecipeLevelUser] = None,
        primary_user_in_callback: Optional[User] = None,
        user_id_in_callback: Optional[str] = None,
        recipe_user_id_in_callback: Optional[str] = None,
        core_call_count: int = 0,
        store: Dict[str, Any] = {},  # pylint: disable=dangerous-default-value
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
        respon_json = {
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
            "sendEmailToRecipeUserId": (
                # this is intentionally done this way cause the test in the test suite expects this way.
                {"recipeUserId": self.send_email_to_recipe_user_id}
                if self.send_email_to_recipe_user_id is not None
                else None
            ),
            "userInCallback": (
                self.user_in_callback.to_json()
                if self.user_in_callback is not None
                else None
            ),
            "email": self.email,
            "newAccountInfoInCallback": (
                self.new_account_info_in_callback.to_json()
                if self.new_account_info_in_callback is not None
                else None
            ),
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
        # Filter out items that are None
        respon_json = {k: v for k, v in respon_json.items() if v is not None}
        return respon_json


def get_override_params() -> OverrideParams:
    return OverrideParams(
        send_email_to_user_id=send_email_to_user_id,
        token=token,
        user_post_password_reset=user_post_password_reset,
        email_post_password_reset=email_post_password_reset,
        send_email_callback_called=send_email_callback_called,
        send_email_to_user_email=send_email_to_user_email,
        send_email_inputs=send_email_inputs,  # type: ignore
        send_sms_inputs=send_sms_inputs,  # type: ignore
        send_email_to_recipe_user_id=send_email_to_recipe_user_id,
        user_in_callback=user_in_callback,
        email=email_param,
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
        store=store,  # type: ignore
    )


def reset_override_params():
    global \
        send_email_to_user_id, \
        token, \
        user_post_password_reset, \
        email_post_password_reset, \
        send_email_callback_called, \
        send_email_to_user_email, \
        send_email_inputs, \
        send_sms_inputs, \
        send_email_to_recipe_user_id, \
        user_in_callback, \
        email_param, \
        primary_user_in_callback, \
        new_account_info_in_callback, \
        user_id_in_callback, \
        recipe_user_id_in_callback, \
        store
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
    email_param = None
    primary_user_in_callback = None
    new_account_info_in_callback = None
    user_id_in_callback = None
    recipe_user_id_in_callback = None
    store = {}
    Info.core_call_count = 0


# Global variable declarations
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
email_param = None
primary_user_in_callback = None
new_account_info_in_callback = None
user_id_in_callback = None
recipe_user_id_in_callback = None
store = {}
