
# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [unreleased]

## [0.23.1] - 2024-07-09

### Changes

-   `refresh_post` and `refresh_session` now clears all user tokens upon CSRF failures and if no tokens are found. See the latest comment on https://github.com/supertokens/supertokens-node/issues/141 for more details.
-   Adds `jwks_refresh_interval_sec` config to `session.init` to set the default JWK cache duration. The default is 4 hours.

## [0.23.0] - 2024-06-24

### Breaking change

- The access token cookie expiry has been changed from 100 years to 1 year due to some browsers capping the maximum expiry at 400 days. No action is needed on your part.

## [0.22.1] - 2024-06-10
- Remove `user_context` being `None` check in querier delete function to make it consistent with other non GET functions

## [0.22.0] - 2024-06-05
- Adds caching per API based on user context.

### Breaking change:
- Changes general error in querier to normal python error.

## [0.21.0] - 2024-05-23

### Breaking change

-   Removed ThirdPartyEmailPassword and ThirdPartyPasswordless recipes. Instead, you should use ThirdParty + EmailPassword or ThirdParty + Passwordless recipes separately in your recipe list.
-   Removed `rid` query param from:
    -   email verification links
    -   passwordless magic links
    -   password reset links

### Changes

-   If `rid` header is present in an API call, the routing no only only depends on that. If the SDK cannot resolve a request handler based on the `rid`, request path and method, it will try to resolve a request handler only based on the request path and method (therefore ignoring the `rid` header).
-   New API handlers are:
    -   `GET /emailpassword/email/exists` => email password, does email exist API (used to be `GET /signup/email/exists` with `rid` of `emailpassword` or `thirdpartyemailpassword` which is now deprecated)
    -   `GET /passwordless/email/exists` => email password, does email exist API (used to be `GET /signup/email/exists` with `rid` of `passwordless` or `thirdpartypasswordless` which is now deprecated)
    -   `GET /passwordless/phonenumber/exists` => email password, does email exist API (used to be `GET /signup/phonenumber/exists` which is now deprecated)
-   Support for FDI 2.0

### Migration guide

-   If you were using `ThirdPartyEmailPassword`, you should now init `ThirdParty` and `EmailPassword` recipes separately. The config for the individual recipes are mostly the same, except the syntax may be different. Check our recipe guides for [ThirdParty](https://supertokens.com/docs/thirdparty/introduction) and [EmailPassword](https://supertokens.com/docs/emailpassword/introduction) for more information.

-   If you were using `ThirdPartyPasswordless`, you should now init `ThirdParty` and `Passwordless` recipes separately. The config for the individual recipes are mostly the same, except the syntax may be different. Check our recipe guides for [ThirdParty](https://supertokens.com/docs/thirdparty/introduction) and [Passwordless](https://supertokens.com/docs/passwordless/introduction) for more information.

- The way to get user information has changed:
    - If you are using `get_users_by_email` from `thirdpartyemailpassword` recipe:
    
        Before:
        ```python
        from supertokens_python.recipe.thirdpartyemailpassword.syncio import get_users_by_email

        user_info = get_users_by_email("public", "test@example.com")
        ```

        After:
        ```python
        from supertokens_python.recipe.thirdparty.syncio import get_users_by_email as get_users_by_email_third_party
        from supertokens_python.recipe.emailpassword.syncio import get_user_by_email as get_user_by_email_emailpassword
        
        third_party_user_info = get_users_by_email_third_party("public", "test@example.com")

        email_password_user_info = get_user_by_email_emailpassword("public", "test@example.com")

        if email_password_user_info is not None:
            print(email_password_user_info)
        
        if len(third_party_user_info) > 0:
            print(third_party_user_info)
        ```

    - If you are using `get_user_id` from `thirdpartyemailpassword` recipe:
    
        Before:
        ```python
        from supertokens_python.recipe.thirdpartyemailpassword.syncio import get_user_by_id

        _ = get_user_by_id(user_id)
        ```

        After:
        ```python
        from supertokens_python.recipe.thirdparty.syncio import (
            get_user_by_id as get_user_by_id_thirdparty,
        )
        from supertokens_python.recipe.emailpassword.syncio import (
            get_user_by_id as get_user_by_id_emailpassword,
        )

        thirdparty_user = get_user_by_id_thirdparty(user_id)
        if thirdparty_user is None:
            email_password_user = get_user_by_id_emailpassword(user_id)
            if email_password_user is not None:
                print(email_password_user)
        else:
            print(thirdparty_user)
        ```
    
    - If you are using `get_users_by_email` from `thirdpartypasswordless` recipe:
    
        Before:
        ```python
        from supertokens_python.recipe.thirdpartypasswordless.syncio import get_users_by_email

        user_info = get_users_by_email("public", "test@example.com")
        ```

        After:
        ```python
        from supertokens_python.recipe.thirdparty.syncio import get_users_by_email as get_users_by_email_third_party
        from supertokens_python.recipe.passwordless.syncio import get_user_by_email as get_user_by_email_passwordless
        
        third_party_user_info = get_users_by_email_third_party("public", "test@example.com")

        passwordless_user_info = get_user_by_email_passwordless("public", "test@example.com")

        if passwordless_user_info is not None:
            print(passwordless_user_info)
        
        if len(third_party_user_info) > 0:
            print(third_party_user_info)
        ```

    - If you are using `get_user_id` from `thirdpartypasswordless` recipe:
    
        Before:
        ```python
        from supertokens_python.recipe.thirdpartypasswordless.syncio import get_user_by_id

        _ = get_user_by_id(user_id)
        ```

        After:
        ```python
        from supertokens_python.recipe.thirdparty.syncio import (
            get_user_by_id as get_user_by_id_thirdparty,
        )
        from supertokens_python.recipe.passwordless.syncio import (
            get_user_by_id as get_user_by_id_passwordless,
        )

        thirdparty_user = get_user_by_id_thirdparty(user_id)
        if thirdparty_user is None:
            passwordless_user = get_user_by_id_passwordless(user_id)
            if passwordless_user is not None:
                print(passwordless_user)
        else:
            print(thirdparty_user)
        ```

## [0.20.2] - 2024-05-17

-   Improves FastAPI middleware performance using recommended ASGI middleware implementation.

## [0.20.1] - 2024-05-10

-   Fixes parameter mismatch in generating fake email

## [0.20.0] - 2024-05-08

-   Added `older_cookie_domain` config option in the session recipe. This will allow users to clear cookies from the older domain when the `cookie_domain` is changed.
-   If `verify_session` detects multiple access tokens in the request, it will return a 401 error, prompting a refresh, even if one of the tokens is valid.
-   `refresh_post` (`/auth/session/refresh` by default) API changes:
    -   now returns 500 error if multiple access tokens are present in the request and `config.older_cookie_domain` is not set.
    -   now clears the access token cookie if it was called without a refresh token (if an access token cookie exists and if using cookie-based sessions).
    -   now clears cookies from the old domain if `older_cookie_domain` is specified and multiple refresh/access token cookies exist, without updating the front-token or any of the tokens.
    -   now a 200 response may not include new session tokens.
-   Fixed a bug in the `normalise_session_scope` util function that caused it to remove leading dots from the scope string.

### Migration

With this update, the second argument in the `session.init` function changes from `cookie_secure` to `older_cookie_domain`. If you're using positional arguments, you need to insert `None` for `older_cookie_domain` as the second argument to maintain the correct order of parameters.

Before:
```python
from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import session

init(
    supertokens_config=SupertokensConfig("..."),
    app_info=InputAppInfo("..."),
    framework="...",
    recipe_list=[
        session.init(
            "example.com" # cookie_domain
            True, # cookie_secure
            "strict" # cookie_same_site
        ),
    ],
)
```

After the update:

```python
from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import session

init(
    supertokens_config=SupertokensConfig("..."),
    app_info=InputAppInfo("..."),
    framework="...",
    recipe_list=[
        session.init(
            "example.com" # cookie_domain
            None, # older_cookie_domain
            True, # cookie_secure
            "strict" # cookie_same_site
        ),
    ],
)
```

### Rationale

This update addresses an edge case where changing the `cookie_domain` config on the server can lead to session integrity issues. For instance, if the API server URL is 'api.example.com' with a cookie domain of '.example.com', and the server updates the cookie domain to 'api.example.com', the client may retain cookies with both '.example.com' and 'api.example.com' domains, resulting in multiple sets of session token cookies existing.

Previously, verify_session would select one of the access tokens from the incoming request. If it chose the older cookie, it would return a 401 status code, prompting a refresh request. However, the `refresh_post` API would then set new session token cookies with the updated `cookie_domain`, but older cookies will persist, leading to repeated 401 errors and refresh loops.

With this update, verify_session will return a 401 error if it detects multiple access tokens in the request, prompting a refresh request. The `refresh_post` API will clear cookies from the old domain if `older_cookie_domain` is specified in the configuration, then return a 200 status. If `older_cookie_domain` is not configured, the `refresh_post` API will return a 500 error with a message instructing to set `older_cookie_domain`.

**Example:**

-   `apiDomain`: 'api.example.com'
-   `cookie_domain`: 'api.example.com'

**Flow:**

1. After authentication, the frontend has cookies set with `domain=api.example.com`, but the access token has expired.
2. The server updates `cookie_domain` to `.example.com`.
3. An API call requiring session with an expired access token (cookie with `domain=api.example.com`) results in a 401 response.
4. The frontend attempts to refresh the session, generating a new access token saved with `domain=.example.com`.
5. The original API call is retried, but because it sends both the old and new cookies, it again results in a 401 response.
6. The frontend tries to refresh the session with multiple access tokens:
    - If `older_cookie_domain` is not set, the refresh fails with a 500 error.
        - The user remains stuck until they clear cookies manually or `older_cookie_domain` is set.
    - If `older_cookie_domain` is set, the refresh clears the older cookie, returning a 200 response.
        - The frontend retries the original API call, sending only the new cookie (`domain=.example.com`), resulting in a successful request.

## [0.19.0] - 2024-05-06

-  `create_new_session` now defaults to the value of the `st-auth-mode` header (if available) if the configured `get_token_transfer_method` returns `any`.
- Enable smooth switching between `use_dynamic_access_token_signing_key` settings by allowing refresh calls to change the signing key type of a session.

### Breaking change:
- A session is not required when calling the sign out API. Otherwise the API will return a 401 error.

## [0.18.11] - 2024-04-26

- Fixes issues with the propagation of session creation/updates with django-rest-framework because the django-rest-framework wrapped the original request with it's own request object. Updates on that object were not reflecting on the original request object.
- Fixes type mismatch for FastAPI middleware.

## [0.18.10] - 2024-04-05

- Relax constraints on `aiosmtplib` dependency version.

## [0.18.9] - 2024-03-14

- Updates version for CICD testing
- Fixes session recipe to not pass tenant id when `revoke_across_all_tenants` or `fetch_across_all_tenants` is set to `True`
- Updated fake email generation

## [0.18.8] - 2024-02-29

- Fixes dashboard URI path. Now it returns the complete user given path instead of just the normalized connectionURI domain.

## [0.18.7] - 2024-01-17

- Fixes `connection_uri` normalisation in the dashboard recipe.
- Fixes issue with fetching of thirdparty passwordless user in dashboard: https://github.com/supertokens/supertokens-python/issues/472

## [0.18.6] - 2024-01-12

- Relax constraints on `httpx` dependency version.

## [0.18.5] - 2023-12-14

- Fixes an incompatibility issue with Django version 4.0 and above.

## [0.18.4] - 2023-12-12

- CI/CD changes

## [0.18.3] - 2023-12-07

- Fixes security issue with shared `g` objects from gunicorn: https://github.com/supertokens/supertokens-python/issues/463

## [0.18.2] - 2023-12-05

- Updates LinkedIn OAuth implementation as per the latest [changes](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2?context=linkedin%2Fconsumer%2Fcontext#authenticating-members).

## [0.18.1] - 2023-12-01

- Fixes bug in dashboard recipe where we did not expose `USER_EMAIL_VERIFY_TOKEN_API` API.

## [0.18.0] - 2023-11-25

### Added

-   Adds support for configuring multiple frontend domains to be used with the same backend
-   Added new `origin` property to `InputAppInfo`, this can be configured to allow you to conditionally return the value of the frontend domain. This property will replace `website_domain`
-   `website_domain` inside `InputAppInfo` is now optional. Using `origin` recommended over using `website_domain`. Using `website_domain` will continue to work.

### Breaking Change
- The order or arguments in the `InputAppInfo` has changed. If NOT using keyword arguments for `app_info` in `supertokens.init`, then you will have to move `website_domain` like so:

    Before:
    ```python
    init(
        app_info=InputAppInfo(
            "app_name",
            "api_domain",
            "website_domain",
            None, # api_gateway_path
            None, # api_base_path
            None, # website_base_path
        ),
        # other configs..
    )
    ```

    After:
    ```python
    init(
        app_info=InputAppInfo(
            "app_name",
            "api_domain",
            None, # api_gateway_path
            None, # api_base_path
            None, # website_base_path
            "website_domain"
        ),
        # other configs..
    )
    ```

- In the session recipe, if there is an `UNAUTHORISED` or `TOKEN_THEFT_DETECTED` error, the session tokens are cleared in the response regardless of if you have provided your own `error_handlers` in `session.init` 

## [0.17.0] - 2023-11-14
- Fixes `create_reset_password_link` in the emailpassword recipe wherein we passed the `rid` instead of the token in the link

### Breaking fix
- Fixed spelling of `CreateResetPasswordLinkUnknownUserIdError` in `create_reset_password_link`. It used to be `CreateResetPasswordLinkUknownUserIdError`

## [0.16.8] - 2023-11-7

### Added

- Added `network_interceptor` to the `supertokens_config` in `init`.
  - This can be used to capture/modify all the HTTP requests sent to the core.
  - Solves the issue - https://github.com/supertokens/supertokens-core/issues/865

### Fixes
- The sync functions `create_user_id_mapping` and `delete_user_id_mapping` now take the `force` parameter as an optional argument, just like their async counterparts.
- Functions `get_users_oldest_first`, `get_users_newest_first`, `get_user_count`, `delete_user`, `create_user_id_mapping`, `get_user_id_mapping`, `delete_user_id_mapping` and `update_or_delete_user_id_mapping_info` now accept `user_context` as an optional argument.
- Fixed the dependencies in the example apps
  - Example apps will now fetch the latest version of the frameworks

## [0.16.7] - 2023-11-2

- Added `debug` flag in `init()`. If set to `True`, debug logs will be printed.

## [0.16.6] - 2023-10-24

- Fixed server error in `sign_in_up` API
    - There was a bug in case where the API was called with just oAuth tokens without passing the `redirect_uri_info`.

## [0.16.5] - 2023-10-23

- Relaxed constraint on `pyJWT` dependency.
  - This is done because some users face `InvalidSignatureError` when decoding the id token with the latest `pyJWT` version.

## [0.16.4] - 2023-10-05

- Add `validate_access_token` function to providers
    - This can be used to verify the access token received from providers.
    - Implemented `validate_access_token` for the Github provider.

## [0.16.3] - 2023-09-28

- Add Twitter provider for thirdparty login
- Add `Cache-Control` header for jwks endpoint `/jwt/jwks.json`
- Add `validity_in_secs` to the return value of overridable `get_jwks` recipe function.
    - This can be used to control the `Cache-Control` header mentioned above.
    - It defaults to `60` or the value set in the cache-control header returned by the core
    - This is optional (so you are not required to update your overrides). Returning `None` means that the header won't be set

## [0.16.2] - 2023-09-20

- Allow use of [nest-asyncio](https://pypi.org/project/nest-asyncio/) when env var `SUPERTOKENS_NEST_ASYNCIO=1`.
- Retry Querier request on `AsyncLibraryNotFoundError`

## [0.16.1] - 2023-09-19
- Handle AWS Public URLs (ending with `.amazonaws.com`) separately while extracting TLDs for SameSite attribute.


## [0.16.0] - 2023-09-13


### Added

-   The Dashboard recipe now accepts a new `admins` property which can be used to give Dashboard Users write privileges for the user dashboard.

### Changes

-   Dashboard APIs now return a status code `403` for all non-GET requests if the currently logged in Dashboard User is not listed in the `admins` array
- Now ignoring protected props in the payload in `create_new_session` and `create_new_session_without_request_response`

## [0.15.3] - 2023-09-25

- Handle 429 rate limiting from SaaS core instances


## [0.15.2] - 2023-09-23

- Fixed bugs in thirdparty providers: Bitbucket, Boxy-SAML, and Facebook

## [0.15.1] - 2023-09-22
- Fixes name of passwordless recipe function from `passwordlessSigninup` to `passwordless_signinup`

## [0.15.0] - 2023-09-22

-   Fixes apple redirect
-   Fixes an issue where the user management dashboard would incorrectly show an email as unverified even if it was verified

### Added

-   Added Multitenancy Recipe & always initialized by default.
-   Adds Multitenancy support to all the recipes
-   Added new Social login providers - LinkedIn
-   Added new Multi-tenant SSO providers - Okta, Active Directory, Boxy SAML
-   All APIs handled by Supertokens middleware can have an optional `tenantId` prefixed in the path. e.g. `<basePath>/<tenantId>/signinup`
-   Following recipe functions (asyncio/syncio) have been added:
    -   `EmailPassword`
        - `create_reset_password_link`
        - `send_reset_password_email`
    -   `EmailVerification`
        - `create_email_verification_link`
        - `send_email_verification_email`
    -   `ThirdParty`
        - `get_provider`
    -   `ThirdPartyEmailPassword`
        - `third_party_get_provider`
        - `create_reset_password_link`
        - `send_reset_password_email`
    -   `ThirdPartyPasswordless`
        - `third_party_get_provider`
        - `create_reset_password_link`
        - `send_reset_password_email`

### Breaking changes

-   Only supporting FDI 1.17
-   Core must be upgraded to 6.0
-   `get_users_oldest_first` & `get_users_newest_first` has mandatory parameter `tenant_id`. Pass `'public'` if not using multitenancy.
-   Added mandatory field `tenant_id` to `EmailDeliveryInterface` and `SmsDeliveryInterface`. Pass `'public'` if not using multitenancy.
-   Removed deprecated config `create_and_send_custom_email` and `create_and_send_custom_text_message`.
-   EmailPassword recipe changes:
    -   Added mandatory `tenant_id` field to `TypeEmailPasswordPasswordResetEmailDeliveryInput`
    -   Removed `reset_password_using_token_feature` from `TypeInput`
    -   Added `tenant_id` param to `validate` function in `TypeInputFormField`
    -   Added mandatory `tenant_id` as first parameter to the following recipe index functions:
        -   `sign_up`
        -   `sign_in`
        -   `get_user_by_email`
        -   `create_reset_password_token`
        -   `reset_password_using_token`
    -   Added mandatory `tenantId` in the input for the following recipe interface functions. If any of these functions are overridden, they need to be updated accordingly:
        -   `sign_up`
        -   `sign_in`
        -   `get_user_by_email`
        -   `create_reset_password_token`
        -   `reset_password_using_token`
        -   `update_email_or_password`
    -   Added mandatory `tenantId` in the input for the following API interface functions. If any of these functions are overridden, they need to be updated accordingly:
        -   `email_exists_get`
        -   `generate_password_reset_token_post`
        -   `password_reset_post`
        -   `sign_in_post`
        -   `sign_up_post`
-   EmailVerification recipe changes:
    -   Added mandatory `tenant_id` field to `TypeEmailVerificationEmailDeliveryInput`
    -   Added mandatory `tenant_id` as first parameter to the following recipe index functions:
        -   `create_email_verification_token`
        -   `verify_email_using_token`
        -   `revoke_email_verification_tokens`
    -   Added mandatory `tenantId` in the input for the following recipe interface functions. If any of these functions are overridden, they need to be updated accordingly:
        -   `create_email_verification_token`
        -   `verify_email_using_token`
        -   `revoke_email_verification_tokens`
    -   Added mandatory `tenantId` in the input for the following API interface functions. If any of these functions are overridden, they need to be updated accordingly:
        -   `verify_email_post`
-   Passwordless recipe changes:
    -   Added `tenant_id` param to `validate_email_address`, `validate_phone_number` and `get_custom_user_input_code` functions in `TypeInput`
    -   Added mandatory `tenant_id` field to `TypePasswordlessEmailDeliveryInput` and `TypePasswordlessSmsDeliveryInput`
    -   Added mandatory `tenant_id` in the input to the following recipe index functions:
        -   `create_code`
        -   `create_new_code_for_device`
        -   `get_user_by_email`
        -   `get_user_by_phone_number`
        -   `update_user`
        -   `revoke_code`
        -   `list_codes_by_email`
        -   `list_codes_by_phone_number`
        -   `list_codes_by_device_id`
        -   `list_codes_by_pre_auth_session_id`
        -   `sign_in_up`
    -   Added mandatory `tenant_id` in the input for the following recipe interface functions. If any of these functions are overridden, they need to be updated accordingly:
        -   `create_code`
        -   `create_new_code_for_device`
        -   `consume_code`
        -   `get_user_by_email`
        -   `get_user_by_phone_number`
        -   `revoke_all_codes`
        -   `revoke_code`
        -   `list_codes_by_email`
        -   `list_codes_by_phone_number`
        -   `list_codes_by_device_id`
        -   `list_codes_by_pre_auth_session_id`
    -   Added mandatory `tenant_id` in the input for the following API interface functions. If any of these functions are overridden, they need to be updated accordingly:
        -   `create_code_post`
        -   `resend_code_post`
        -   `consume_code_post`
        -   `email_exists_get`
        -   `phone_number_exists_get`
-   ThirdParty recipe changes
    -   The providers array in `sign_in_up_feature` accepts `List[ProviderInput]` instead of `List[Provider]`. `Provider` interface is re-written. Refer migration section for more info.
    -   Removed `sign_in_up` and added `manually_create_or_update_user` instead in the recipe index functions.
    -   Added `manually_create_or_update_user` to recipe interface which is being called by the function mentioned above.
        -   `manually_create_or_update_user` recipe interface function should not be overridden as it is not going to be called by the SDK in the sign in/up flow.
        -   `sign_in_up` recipe interface functions is not removed and is being used by the sign in/up flow.
    -   Added mandatory `tenant_id` as first parameter to the following recipe index functions:
        -   `get_users_by_email`
        -   `get_user_by_third_party_info`
    -   Added mandatory `tenant_id` in the input for the following recipe interface functions. If any of these functions are overridden, they need to be updated accordingly:
        -   `get_users_by_email`
        -   `get_user_by_third_party_info`
        -   `sign_in_up`
    -   Added mandatory `tenant_id` in the input for the following API interface functions. If any of these functions are overridden, they need to be updated accordingly:
        -   `authorisation_url_get`
        -   `sign_in_up_post`
    -   Updated `sign_in_up` recipe interface function in thirdparty with new parameters:
        -   `o_auth_tokens` - contains all the tokens (access_token, id_token, etc.) as returned by the provider
        -   `raw_user_info_from_provider` - contains all the user profile info as returned by the provider
    -   Updated `authorisation_url_get` API
        -   Changed: Doesn't accept `client_id` anymore and accepts `client_type` instead to determine the matching config
        -   Added: optional `pkce_code_verifier` in the response, to support PKCE
    -   Updated `sign_in_up_post` API
        -   Removed: `client_id`, `redirect_uri`, `auth_code_response` and `code` from the input
        -   Instead,
            -   accepts `client_type` to determine the matching config
            -   One of redirectURIInfo (for code flow) or oAuthTokens (for token flow) is required
    -   Updated `apple_redirect_handler_post`
        -   to accept all the form fields instead of just the code
        -   to use redirect URI encoded in the `state` parameter instead of using the websiteDomain config.
        -   to use HTTP 303 instead of javascript based redirection.
-   Session recipe changes
    -   Added mandatory `tenant_id` as first parameter to the following recipe index functions:
        -   `create_new_session`
        -   `create_new_session_without_request_response`
        -   `validate_claims_in_jwt_payload`
    -   Added mandatory `tenant_id` in the input for the following recipe interface functions. If any of these functions are overridden, they need to be updated accordingly:
        -   `create_new_session`
        -   `get_global_claim_validators`
    -   Added `tenant_id` and `revoke_across_all_tenants` params to `revoke_all_sessions_for_user` in the recipe interface.
    -   Added `tenant_id` and `fetch_across_all_tenants` params to `get_all_session_handles_for_user` in the recipe interface.
    -   Added `get_tenant_id` function to `SessionContainerInterface`
    -   Added `tenant_id` to `fetch_value` function in `PrimitiveClaim`, `PrimitiveArrayClaim`.
-   UserRoles recipe changes
    -   Added mandatory `tenant_id` as first parameter to the following recipe index functions:
        -   `add_role_to_user`
        -   `remove_user_role`
        -   `get_roles_for_user`
        -   `get_users_that_have_role`
    -   Added mandatory `tenant_id` in the input for the following recipe interface functions. If any of these functions are overridden, they need to be updated accordingly:
        -   `add_role_to_user`
        -   `remove_user_role`
        -   `get_roles_for_user`
        -   `get_roles_for_user`
-   Similar changes in combination recipes (thirdpartyemailpassword and thirdpartypasswordless) have been made
-   Even if thirdpartyemailpassword and thirdpartpasswordless recipes do not have a providers array as an input, they will still expose the third party recipe routes to the frontend.
-   Returns 400 status code in emailpassword APIs if the input email or password are not of type string.

### Changes

-   Recipe function changes:
    -   Added optional `tenant_id_for_password_policy` param to `EmailPassword.update_email_or_password`, `ThirdPartyEmailPassword.update_email_or_password`
    -   Added optional param `tenant_id` to `Session.revoke_all_sessions_for_user`. If tenantId is undefined, sessions are revoked across all tenants
    -   Added optional param `tenant_id` to `Session.get_all_session_handles_for_user`. If tenantId is undefined, sessions handles across all tenants are returned
-   Adds optional param `tenant_id` to `get_user_count` which returns total count across all tenants if not passed.
-   Adds protected prop `tId` to the accessToken payload
-   Adds `includes_any` claim validator to `PrimitiveArrayClaim`

### Fixes

-   Fixed an issue where certain Dashboard API routes would return a 404 for Hapi

### Migration

-   To call any recipe function that has `tenant_id` added to it, pass `'public`'

    Before:

    ```python
    emailpassword.asyncio.sign_up("test@example.com", "password")
    ```

    After:

    ```python
    emailpassword.asyncio.sign_up("public", "test@example.com", "password")
    ```

-   Input for provider array change as follows:

    Before:

    ```python
    google_provider = thirdparty.Google(
        client_id="...",
        client_secret="...",
    )
    ```

    After:

    ```python
    google_provider = thirdparty.ProviderConfig(
        third_party_id="google",
        clients=[thirdparty.ProviderClientConfig(client_id="...", client_secret="...")],
    )
    ```

-   Single instance with multiple clients of each provider instead of multiple instances of them. Also use `client_type` to differentiate them. `client_type` passed from the frontend will be used to determine the right config. `is_default` option has been removed and `client_type` is expected to be passed when there are more than one client. If there is only one client, `client_type` is optional and will be used by default.

    Before:

    ```python
    providers = [
        thirdparty.Google(
            is_default=True,
            client_id="clientid1",
            client_secret="...",
        ),
        thirdParty.Google(
            client_id="clientid2",
            client_secret="...",
        ),
    ]
    ```

    After:

    ```python
    providers = [
        thirdparty.ProviderConfig(
            third_party_id="google",
            clients=[
                thirdparty.ProviderClientConfig(client_type="web", client_id= "clientid1", client_secret= "..."),
                thirdparty.ProviderClientConfig(client_type="mobile", client_id="clientid2", client_secret="..."),
            ],
        )
    ]
    ```

-   Change in the implementation of custom providers

    -   All config is part of `ProviderInput`
    -   To provide implementation for `get_profile_info`
        -   either use `user_info_endpoint`, `user_info_endpoint_query_params` and `user_info_map` to fetch the user info from the provider
        -   or specify custom implementation in an override for `get_user_info` (override example in the next section)

    Before:

    ```python
    class CustomProvider(Provider):
        def get_access_token_api_info(
            self,
            redirect_uri: str,
            auth_code_from_request: str,
            user_context: Dict[str, Any],
        ) -> AccessTokenAPI:
            params = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "...",
                "code": auth_code_from_request,
                "redirect_uri": redirect_uri,
            }
            return AccessTokenAPI(self.access_token_api_url, params)

        def get_authorisation_redirect_api_info(
            self, user_context: Dict[str, Any]
        ) -> AuthorisationRedirectAPI:
            params: Dict[str, Any] = {
                "scope": "...",
                "response_type": "...",
                "client_id": self.client_id,
            }
            return AuthorisationRedirectAPI(self.authorisation_redirect_url, params)

        def get_redirect_uri(self, user_context: Dict[str, Any]) -> Union[None, str]:
            return None

        def get_client_id(self, user_context: Dict[str, Any]) -> str:
            return self.client_id

        async def get_profile_info(
            self, auth_code_response: Dict[str, Any], user_context: Dict[str, Any]
        ) -> UserInfo:
            return UserInfo(id="...", UserInfoEmail(email="...", True))
    ```

    After:

    ```python
    custom_provider = thirdparty.Provider(
        config=thirdparty.ProviderConfig(
            third_party_id="custom",
            clients=[
                thirdparty.ProviderConfigClient(
                    client_id="...",
                    client_secret="...",
                ),
            ],
            authorization_endpoint="...",
            authorization_endpoint_query_params={},
            token_endpoint="...",
            token_endpoint_body_params={},
            user_info_endpoint="...",
            user_info_endpoint_query_params={},
            user_info_map=UserInfoMap(
                from_user_info_api=UserFields(
                    user_id="id",
                    email="email",
                    email_verified="email_verified",
                ),
            ),
        ),
    )
    ```

    Also, if the custom provider supports openid, it can automatically discover the endpoints

    ```python
    custom_provider = thirdparty.ProviderInput(
        config=thirdparty.ProviderConfig(
            third_party_id="custom",
            clients=[
                thirdparty.ProviderConfigClient(
                    client_id="...",
                    client_secret="...",
                ),
            ],
            oidc_discovery_endpoint="...",
            user_info_map=UserInfoMap(
                from_user_info_api=UserFields(
                    user_id="id",
                    email="email",
                    email_verified="email_verified",
                ),
            ),
        ),
    )
    ```

    Note: The SDK will fetch the oauth2 endpoints from the provider's OIDC discovery endpoint. No need to `/.well-known/openid-configuration` to the `oidcDiscoveryEndpoint` config. For eg. if `oidcDiscoveryEndpoint` is set to `"https://accounts.google.com/"`, the SDK will fetch the endpoints from `"https://accounts.google.com/.well-known/openid-configuration"`

-   Any of the functions in the TypeProvider can be overridden for custom implementation

    -   Overrides can do the following:
        -   update params, headers dynamically for the authorization redirect url or in the exchange of code to tokens
        -   add custom logic to exchange code to tokens
        -   add custom logic to get the user info

    ```python
    def override(oi):
        oi_get_authorisation_redirect_url = oi.get_authorisation_redirect_url
        oi_exchange_auth_code_for_oauth_tokens = oi.exchange_auth_code_for_oauth_tokens
        oi_get_user_info = oi.get_user_info

        async def get_authorisation_redirect_url(  # pylint: disable=no-self-use
            redirect_uri_on_provider_dashboard: str,
            user_context: Dict[str, Any],
        ) -> AuthorisationRedirect:
            res = await oi_get_authorisation_redirect_url(redirect_uri_on_provider_dashboard, user_context)
            # ...
            return res

        async def exchange_auth_code_for_oauth_tokens(  # pylint: disable=no-self-use
            redirect_uri_info: RedirectUriInfo,
            user_context: Dict[str, Any],
        ) -> Dict[str, Any]:
            res = await oi_exchange_auth_code_for_oauth_tokens(redirect_uri_info, auth_code, user_context)
            # ...
            return res

        async def get_user_info(  # pylint: disable=no-self-use
            oauth_tokens: Dict[str, Any],
            user_context: Dict[str, Any],
        ) -> UserInfo:
            res = await oi_get_user_info(oauth_tokens, user_context)
            # ...
            return res

        oi.get_authorisation_redirect_url = get_authorisation_redirect_url
        oi.exchange_auth_code_for_oauth_tokens = exchange_auth_code_for_oauth_tokens
        oi.get_user_info = get_user_info

        return oi

    custom_provider = thirdparty.ProviderInput(
        config=thirdparty.ProviderConfig(
            third_party_id="custom",
            clients=[
                thirdparty.ProviderConfigClient(
                    client_id="...",
                    client_secret="...",
                ),
            ],
            oidc_discovery_endpoint="...",
            user_info_map=UserInfoMap(
                from_user_info_api=UserFields(
                    user_id="id",
                    email="email",
                    email_verified="email_verified",
                ),
            ),
        ),
        override=override
    )
    ```

-   To get access token and raw user info from the provider, override the signInUp function

    ```python
    def override_functions(oi):
        oi_sign_in_up = oi.sign_in_up

        async def sign_in_up(
            third_party_id: str,
            third_party_user_id: str,
            email: str,
            oauth_tokens: Dict[str, Any],
            raw_user_info_from_provider: RawUserInfoFromProvider,
            tenant_id: str,
            user_context: Dict[str, Any],
        ) -> SignInUpOkResult:
            res = await oi_sign_in_up(third_party_id, third_party_user_id, email, oauth_tokens, raw_user_info_from_provider, tenant_id, user_context)
            # res.oauth_tokens['access_token']
            # res.oauth_tokens['id_token']
            # res.raw_user_info_from_provider.from_user_info_api
            # res.raw_user_info_from_provider.from_id_token_payload
            return res

    thirdparty.init(
        override=thirdparty.InputOverrideConfig(functions=override_functions)
    )
    ```

-   Request body of thirdparty signinup API has changed

    -   If using auth code:

        Before:

        ```json
        {
            "thirdPartyId": "...",
            "clientId": "...",
            "redirectURI": "...", // optional
            "code": "..."
        }
        ```

        After:

        ```json
        {
            "thirdPartyId": "...",
            "clientType": "...",
            "redirectURIInfo": {
                "redirectURIOnProviderDashboard": "...", // required
                "redirectURIQueryParams": {
                    "code": "...",
                    "state": "..."
                    // ... all callback query params
                },
                "pkceCodeVerifier": "..." // optional, use this if using PKCE flow
            }
        }
        ```

    -   If using tokens:

        Before:

        ```json
        {
            "thirdPartyId": "...",
            "clientId": "...",
            "redirectURI": "...",
            "authCodeResponse": {
                "access_token": "...", // required
                "id_token": "..."
            }
        }
        ```

        After:

        ```json
        {
            "thirdPartyId": "...",
            "clientType": "...",
            "oAuthTokens": {
                "access_token": "...", // now optional
                "id_token": "..."
                // rest of the oAuthTokens as returned by the provider
            }
        }
        ```
### SDK and core compatibility

- Compatible with Core>=6.0.0 (CDI 4.0)
- Compatible with frontend SDKs:
    - supertokens-auth-react@0.34.0
    - supertokens-web-js@0.7.0
    - supertokens-website@17.0.2


## [0.14.8] - 2023-07-07
## Fixes

- Anti csrf check should happen only when access token is passed while session is optional
- `verify_session` middleware now handles supertokens related errors as well.

## [0.14.7] - 2023-07-03
- Fixes error message in querier.

## [0.14.6] - 2023-06-22

### Changes and fixes

- Relax constraints on `httpx` dependency version

## [0.14.5] - 2023-06-21

### Changes and fixes

- Remove constraints on `cryptograpy` dependency version and let `pyjwt` library handle it

## [0.14.4] - 2023-06-14

### Changes and fixes

- Use `useStaticSigningKey` instead of `use_static_signing_key` in `create_jwt` function. This was a bug in the code.
- Use request library instead of urllib to fetch JWKS keys ([#344](https://github.com/supertokens/supertokens-python/issues/344))
- Throw error when `verify_sesion` is used with a view that allows `OPTIONS` or `TRACE` requests
- Allow `verify_session` decorator to be with `@app.before_request` in Flask without returning a response


## [0.14.3] - 2023-06-7

### Changes

- Update email templates to fix an issue with styling on some email clients

## [0.14.2] - 2023-05-29

- Adds additional debug logs whenever the SDK throws a `TRY_REFRESH_TOKEN` or `UNAUTHORISED` error to make debugging easier


## [0.14.1] - 2023-05-23

### Changes

-   Added a new `get_request_from_user_context` function that can be used to read the original network request from the user context in overridden APIs and recipe functions

## [0.14.0] - 2023-05-18
- Adds missing `check_database` boolean in `verify_session`

## [0.13.1] - 2023-05-15
### Changes
-   Made the access token string optional in the overrideable `get_session` function
-   Moved checking if the access token is defined into the overrideable `get_session` function

## [0.13.0] - 2023-05-04
### Breaking changes

- Added support for CDI version `2.21`
- Dropped support for CDI version `2.8` - `2.20`
- Changed the interface and configuration of the Session recipe, see below for details. If you do not use the Session recipe directly and do not provide custom configuration, then no migration is necessary.
- `get_access_token_payload` will now return standard (`sub`, `iat`, `exp`) claims and some SuperTokens specific claims along the user defined ones in `get_access_token_payload`.
- Some claim names are now prohibited in the root level of the access token payload:
    - They are: `sub`, `iat`, `exp`, `sessionHandle`, `parentRefreshTokenHash1`, `refreshTokenHash1`, `antiCsrfToken`
    - If you used these in the root level of the access token payload, then you'll need to migrate your sessions or they will be logged out during the next refresh
    - These props should be renamed (e.g., by adding a prefix) or moved inside an object in the access token payload
    - You can migrate these sessions by updating their payload to match your new structure, by calling `merge_into_access_token_payload`
- New access tokens are valid JWTs now
    - They can be used directly (i.e.: by calling `get_access_token` on the session) if you need a JWT
    - The `jwt` prop in the access token payload is removed
- Changed the Session recipe interface - `create_new_session`, `get_session` and `refresh_session` overrides now do not take response and request and return status instead of throwing

### Configuration changes

-   Added `use_dynamic_access_token_signing_key` (defaults to `True`) option to the Session recipe config
-   Added `expose_access_token_to_frontend_in_cookie_based_auth` (defaults to `False`) option to the Session recipe config
-   JWT and OpenId related configuration has been removed from the Session recipe config. If necessary, they can be added by initializing the OpenId recipe before the Session recipe.


### Interface changes

- Renamed `get_session_data` to `get_session_data_from_database` to clarity that it always hits the DB
- Renamed `update_session_data` to `update_session_data_in_database`
- Renamed `session_data` to `session_data_in_database` in `SessionInformation` and the input to `create_new_session`
- Added new `check_database` param to `verify_session` and `get_session`
- Removed `status` from `jwks_get` output (function & API)
- Added new optional `use_static_signing_key` param to `createJWT`
- Removed deprecated `update_access_token_payload` and `regenerate_access_token` from the Session recipe interface
- Removed `get_access_token_lifetime_ms` and `get_refresh_token_lifetime_ms` functions


## Changes

-   The Session recipe now always initializes the OpenID recipe if it hasn't been initialized.
-   Refactored how access token validation is done
-   Removed the handshake call to improve start-up times
-   Added support for new access token version
- added optional password policy check in `update_email_or_password`

### Added

-   Added `create_new_session_without_request_response`, `get_session_without_request_response`, `refresh_session_without_request_response` to the Session recipe.
-   Added `get_all_session_tokens_dangerously` to session objects (`SessionContainer`)
-   Added `attach_to_request_response` to session objects (`SessionContainer`)

### Migration

#### If self-hosting core

1. You need to update the core version
2. There are manual migration steps needed. Check out the core changelogs for more details.

#### If you used the jwt feature of the session recipe

1. Add `expose_access_token_to_frontend_in_cookie_based_auth=true` to the Session recipe config on the backend if you need to access the JWT on the frontend.
2. Choose a prop from the following list. We'll use `sub` in the code below, but you can replace it with another from the list if you used it in a custom access token payload.
    - `sub`
    - `iat`
    - `exp`
    - `sessionHandle`
3. On the frontend where you accessed the JWT before by: `(await Session.getAccessTokenPayloadSecurely()).jwt` update to:

```tsx
let jwt = null;
const accessTokenPayload = await Session.getAccessTokenPayloadSecurely();
if (accessTokenPayload.sub !== undefined) {
    jwt = await Session.getAccessToken();
} else {
    // This branch is only required if there are valid access tokens created before the update
    // It can be removed after the validity period ends
    jwt = accessTokenPayload.jwt;
}
```

4. On the backend if you accessed the JWT before by `session.get_access_token_payload()['jwt']` please update to:

```python
from supertokens_python.recipe.session.interfaces import SessionContainer

session: SessionContainer = ...
access_token_payload = await session.get_access_token_payload()

if access_token_payload.get('sub') is not None:
    jwt = await session.get_access_token()
else:
    # This branch is only required if there are valid access tokens created before the update
    # It can be removed after the validity period ends
    jwt = access_token_payload['jwt']
```

#### If you used to set an issuer in the session recipe `jwt` configuration

-   You can add an issuer claim to access tokens by overriding the `create_new_session` function in the session recipe init.
    -   Check out https://supertokens.com/docs/passwordless/common-customizations/sessions/claims/access-token-payload#during-session-creation for more information
-   You can add an issuer claim to JWTs created by the JWT recipe by passing the `iss` claim as part of the payload.
-   You can set the OpenId discovery configuration as follows:

Before:

```python
from supertokens_python import init
from supertokens_python.recipe import session

init(
    app_info="...",
    recipe_list=[
        session.init(jwt=session.JWTConfig(enable=True, issuer="..."))
    ]
)
```

After:

```python
from typing import Dict, Any
from supertokens_python import init
from supertokens_python.recipe import session, openid
from supertokens_python.recipe.openid.interfaces import RecipeInterface as OpenIDRecipeInterface
from supertokens_python.recipe.openid.interfaces import GetOpenIdDiscoveryConfigurationResult

async def openid_functions_override(oi: OpenIDRecipeInterface):
    async def get_openid_discovery_configuration(_: Dict[str, Any]):
        return GetOpenIdDiscoveryConfigurationResult(
            issuer="your issuer",
            jwks_uri="https://your.api.domain/auth/jwt/keys"
        )

    oi.get_open_id_discovery_configuration = get_openid_discovery_configuration
    return oi

init(
    app_info="...",
    recipe_list=[
        session.init(
            get_token_transfer_method= lambda *_: "header",
            override=session.InputOverrideConfig(
                openid_feature=openid.InputOverrideConfig(
                    functions=openid_functions_override
                )
            )
        )
    ]
)
```

#### If you used `session_data` (not `access_token_payload`)

Related functions/prop names have changes (`session_data` became `session_data_from_database`):

-   Renamed `get_session_data` to `get_session_data_from_database` to clarify that it always hits the DB
-   Renamed `update_session_data` to `update_session_data_in_database`
-   Renamed `session_data` to `session_data_in_database` in `SessionInformationResult` and the input to `create_new_session`

#### If you used to set `access_token_blacklisting` in the core config

-   You should now set `check_database` to true in the `verify_session` params.

#### If you used to set `access_token_signing_key_dynamic` in the core config

-   You should now set `use_dynamic_access_token_signing_key` in the Session recipe config.

#### If you used to use standard/protected props in the access token payload root:

1. Update you application logic to rename those props (e.g., by adding a prefix)
2. Update the session recipe config (in this example `sub` is the protected property we are updating by adding the `app` prefix):

Before:

```python
from typing import Any, Dict, Optional
from supertokens_python.recipe.session.interfaces import RecipeInterface as SessionRecipeInterface
from supertokens_python.recipe import session

async def override_session_functions(oi: SessionRecipeInterface):
    oi_create_new_session = oi.create_new_session

    async def create_new_session(
        user_id: str,
        access_token_payload: Optional[Dict[str, Any]],
        session_data_in_database: Optional[Dict[str, Any]],
        disable_anti_csrf: Optional[bool],
        user_context: Dict[str, Any],
    ):
        return oi_create_new_session(
            user_id,
            {**access_token_payload, "sub": access_token_payload["userId"] + "!!!" }
            session_data_in_database,
            disable_anti_csrf,
            user_context,
        )

    oi.create_new_session = create_new_session

session.init(
    override=session.InputOverrideConfig(functions=override_session_functions)
)
```

After:

```python
from typing import Any, Dict, Optional
from supertokens_python.recipe.session.interfaces import RecipeInterface as SessionRecipeInterface
from supertokens_python.recipe import session

async def override_session_functions(oi: SessionRecipeInterface):
    oi_get_session = oi.get_session
    oi_create_new_session = oi.create_new_session

    async def get_session(
        access_token: str,
        anti_csrf_token: Optional[str],
        anti_csrf_check: Optional[bool] = None,
        check_database: Optional[bool] = None,
        override_global_claim_validators: Optional[
            Callable[
                [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
                MaybeAwaitable[List[SessionClaimValidator]],
            ]
        ] = None,
        user_context: Optional[Dict[str, Any]] = None,
    ):
        result = oi_get_session(input)
        if result:
            orig_payload = result.get_access_token_payload()
            if orig_payload["appSub"] is None:
                await result.merge_into_access_token_payload({"appSub": orig_payload["sub"], "sub": None})

        return result

    async def create_new_session(
        user_id: str,
        access_token_payload: Optional[Dict[str, Any]],
        session_data_in_database: Optional[Dict[str, Any]],
        disable_anti_csrf: Optional[bool],
        user_context: Dict[str, Any],
    ):
        return oi_create_new_session(
            user_id,
            {**access_token_payload, "appSub": access_token_payload["userId"] + "!!!" }
            session_data_in_database,
            disable_anti_csrf,
            user_context
        )

    oi.get_session = get_session
    oi.create_new_session = create_new_session

session.init(
    override=session.InputOverrideConfig(
        functions=override_session_functions,
    )
)
```

#### If you added an override for `create_new_session`/`refresh_session`/`get_session`:

This example uses `get_session`, but the changes required for the other ones are very similar. Before:

```python
from typing import Any, Dict, Optional
from supertokens_python.recipe.session.interfaces import RecipeInterface as SessionRecipeInterface
from supertokens_python.recipe import session


async def override_session_functions():
    oi.get_session = oi.get_session

    async def get_session(
        request: Any,
        access_token: str,
        anti_csrf_token: Optional[str],
        anti_csrf_check: Optional[bool] = None,
        check_database: Optional[bool] = None,
        override_global_claim_validators: Optional[
            Callable[
                [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
                MaybeAwaitable[List[SessionClaimValidator]],
            ]
        ] = None,
        user_context: Optional[Dict[str, Any]] = None,
    ):
        print(request)
        try:
            _session = await oi_get_session(
                request,
                access_token,
                anti_csrf_token,
                anti_csrf_check,
                check_database,
                override_global_claim_validators,
                user_context,
            )
            print(_session)
            return _session
        except Exception as e:
            print(e)
            raise e

session.init(
    override=session.InputOverrideConfig(
        functions=override_session_functions,
    )
)
```

After:

```python
from typing import Any, Dict, Optional
from supertokens_python.recipe.session.interfaces import RecipeInterface as SessionRecipeInterface
from supertokens_python.recipe import session

async def override_session_functions():
    oi.get_session = oi.get_session

    async def get_session(
        access_token: str,
        anti_csrf_token: Optional[str],
        anti_csrf_check: Optional[bool] = None,
        check_database: Optional[bool] = None,
        override_global_claim_validators: Optional[
            Callable[
                [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
                MaybeAwaitable[List[SessionClaimValidator]],
            ]
        ] = None,
        user_context: Optional[Dict[str, Any]] = None,
    ):
        request = user_context["_default"]["request"]
        print(request)

        session_res = await oi_get_session(
            request,
            access_token,
            anti_csrf_token,
            anti_csrf_check,
            check_database,
            override_global_claim_validators,
            user_context,
        )
        if session_res.status == "OK":
            print(session_res.session)
        else:
            print(session_res.status)
            print(session_res.error)

        return session_res


session.init(
    override=session.InputOverrideConfig(
        functions=override_session_functions,
    )
)
```


## [0.12.9] - 2023-04-28

- Added missing arguments in `get_users_newest_first` and `get_users_oldest_first`

## [0.12.8] - 2023-04-19

- Fixed an issues that threw 500 when changing password for user from dashboard

## [0.12.7] - 2023-04-18

- Email template for verify email updated

## [0.12.6] - 2023-03-31

- Adds search APIs to the dashboard recipe

## [0.12.5] - 2023-03-30

- Adds a telemetry API to the dashboard recipe

## [0.12.4] - 2023-03-29
### Changed
- Update all example apps to initialise dashboard recipe

### Added
- Login with gitlab (single tenant only) and bitbucket

## [0.12.3] - 2023-02-27
- Adds APIs and logic to the dashboard recipe to enable email password based login
## [0.12.2] - 2023-02-23
- Fix expiry time of access token cookie.


## [0.12.1] - 2023-02-06

-   Email template updates

# [0.12.0] - 2023-02-03
### Breaking changes

-   The frontend SDK should be updated to a version supporting the header-based sessions!
    -   supertokens-auth-react: >= 0.31.0
    -   supertokens-web-js: >= 0.5.0
    -   supertokens-website: >= 16.0.0
    -   supertokens-react-native: >= 4.0.0
    -   supertokens-ios >= 0.2.0
    -   supertokens-android >= 0.3.0
    -   supertokens-flutter >= 0.1.0
- Only supporting FDI 1.16

### Added

-   Added support for authorizing requests using the `Authorization` header instead of cookies
    -   Added `get_token_transfer_method` config option
    -   Check out https://supertokens.com/docs/thirdpartyemailpassword/common-customizations/sessions/token-transfer-method for more information

### Changed
- Remove constraints on `werkzeug` version


# [0.11.13] - 2023-01-06

- Add missing `original` attribute to flask response and remove logic for cases where `response` is `None`
- Relax PyJWT version constraints https://github.com/supertokens/supertokens-python/issues/272

## [0.11.12] - 2022-12-27
-  Fix django cookie expiry time format to make it consistent with other frameworks: https://github.com/supertokens/supertokens-python/issues/267

## [0.11.11] - 2022-12-26

-   Updates dashboard version
-   Updates user GET API for the dashboard recipe

## [0.11.10] - 2022-12-12

-   Fixes issue of sign up API not sending a `FIELD_ERROR` response in case of duplicate email: https://github.com/supertokens/supertokens-python/issues/264


## [0.11.9] - 2022-12-06

-   Fixes issue where if send_email is overridden with a different email, it will reset that email.

## [0.11.8] - 2022-11-28

### Added:
-   APIs for user details to the dashboard recipe

### Changed:
- Updates dashboard version to 0.2
- Add tests for different scenarios while revoking session during session refresh call

## [0.11.7] - 2022-11-21

- Remove `jsonschema` from package requirements

### Bug fix:
- Update session claims in email verification token generation API in case the session claims are outdated.

## [0.11.6] - 2022-10-27
- Fix cookie_same_site for subdomains [#239](https://github.com/supertokens/supertokens-python/issues/239)

## [0.11.5] - 2022-10-27
- Add `to_json` method to `ClaimValidationError` class.

## [0.11.4] - 2022-10-21
- Relaxes typing_extensions constraint
- Update frontend integration test servers for /angular and /testError tests

## [0.11.3] - 2022-10-17
- Updated google token endpoint.

## [0.11.2] - 2022-10-14
### Changes:
- Removed default `default_max_age` from session claim base classes
- Added a 5 minute `default_max_age` to UserRoleClaim, PermissionClaim and EmailVerificationClaim
- Fix Repetition of root_path in supertokens mididdlware for fastapi [#230](https://github.com/supertokens/supertokens-python/issues/230)

## [0.11.1] - 2022-09-28
### Changes:
- Email verification endpoints will now clear the session if called by a deleted/unknown user

### Additions:
- Adds dashboard recipe
- Added a `username` field to the `SMTPSettings` model for passing custom SMTP server username.

## [0.11.0] - 2022-09-14

### Changes

- Made the `email` parameter optional in `unverify_email`, `revoke_email_verification_tokens`, `is_email_verified`, `verify_email_using_token`, `create_email_verification_token` of the `EmailVerification` recipe.

### Added

- Support for FDI 1.15
- Added support for session claims with related interfaces and classes.
- Added `on_invalid_claim` optional error handler to send InvalidClaim error responses.
- Added `INVALID_CLAIMS` (`InvalidClaimError`) to `SessionErrors`.
- Added `invalid_claim_status_code` optional config to set the status code of InvalidClaim errors.
- Added `override_global_claim_validators` as param of `get_session` and `verify_session`.
- Added `merge_into_access_token_payload` to the Session recipe and session objects which should be preferred to the now deprecated `update_access_token_payload`.
- Added `EmailVerificationClaim`, `UserRoleClaim` and `PermissionClaim`. These claims are now added to the access token payload by default by their respective recipes.
- Added `assert_claims`, `validate_claims_for_session_handle`, `validate_claims_in_jwt_payload` to the Session recipe to support validation of the newly added claims.
- Added `fetch_and_set_claim`, `get_claim_value`, `set_claim_value` and `remove_claim` to the Session recipe to manage claims.
- Added `assert_claims`, `fetch_and_set_claim`, `get_claim_value`, `set_claim_value` and `remove_claim` to session objects to manage claims.
- Added session to the input of `generate_email_verify_token_post`, `verify_email_post`, `is_email_verified_get`.
- Adds default userContext for verifySession calls that contains the request object.

### Breaking Changes
- Removes support for FDI <= 1.14
-   Changed `sign_in_up` third party recipe function to accept just the email as `str` (removed `email_verified: bool`).
-   The frontend SDK should be updated to a version supporting session claims!
    -   supertokens-auth-react: >= 0.25.0
    -   supertokens-web-js: >= 0.2.0
-   `EmailVerification` recipe is now not initialized as part of auth recipes, it should be added to the `recipe_list` directly instead using `emailverification.init()`.
-   Email verification related overrides (`email_verification_feature` attr of `override`) moved from auth recipes into the `EmailVerification` recipe config.
-   Email verification related configs (`email_verification_feature` attr) moved from auth recipes into the `EmailVerification` config object root.
-   ThirdParty recipe no longer takes `email_delivery` config. use `emailverification` recipe's `email_delivery` instead.
-   Moved email verification related configs from the `email_delivery` config of auth recipes into a separate `EmailVerification` email delivery config.
-   Updated return type of `get_email_for_user_id` in the `EmailVerification` recipe config. It should now return an object with status.
-   Removed `get_reset_password_url`, `get_email_verification_url`, `get_link_domain_and_path`. Changing these urls can be done in the email delivery configs instead.
-   Removed `unverify_email`, `revoke_email_verification_tokens`, `is_email_verified`, `verify_email_using_token` and `create_email_verification_token` from auth recipes. These should be called on the `EmailVerification` recipe instead.
-   Changed function signature for email verification APIs to accept a session as an input.
-   Changed Session API interface functions:
    - `refresh_post` now returns a Session container object.
    - `sign_out_post` now takes in an optional session object as a parameter.

### Migration
Before:
```python
from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import emailpassword
from supertokens_python.recipe.emailverification.utils import OverrideConfig

init(
    supertokens_config=SupertokensConfig("..."),
    app_info=InputAppInfo("..."),
    framework="...",
    recipe_list=[
        emailpassword.init(
            # these options should be moved into the EmailVerification config:
            email_verification_feature=emailpassword.InputEmailVerificationConfig("..."),
            override=emailpassword.InputOverrideConfig(
                email_verification_feature=OverrideConfig(
                    # these overrides should be moved into the EmailVerification overrides
                    "..."
                )
            ),
        ),
    ],
)
```

After the update:

```python
from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import emailpassword, emailverification

init(
    supertokens_config=SupertokensConfig("..."),
    app_info=InputAppInfo("..."),
    framework="...",
    recipe_list=[
        emailverification.init(
            "...", # EmailVerification config
            override=emailverification.OverrideConfig(
                # overrides
                "..."
            ),
        ),
        emailpassword.init(),
    ],
)
```

#### Passwordless users and email verification

If you turn on email verification your email-based passwordless users may be redirected to an email verification screen in their existing session.
Logging out and logging in again will solve this problem or they could click the link in the email to verify themselves.

You can avoid this by running a script that will:

1. list all users of passwordless
2. create an emailverification token for each of them if they have email addresses
3. user the token to verify their address

Something similar to this script:

```python
from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import passwordless, emailverification, session
from supertokens_python.recipe.passwordless import ContactEmailOrPhoneConfig


from supertokens_python.syncio import get_users_newest_first
from supertokens_python.recipe.emailverification.syncio import create_email_verification_token, verify_email_using_token
from supertokens_python.recipe.emailverification.interfaces import CreateEmailVerificationTokenOkResult

init(
    supertokens_config=SupertokensConfig("http://localhost:3567"),
    app_info=InputAppInfo(
        app_name="SuperTokens Demo",
        api_domain="https://api.supertokens.io",
        website_domain="supertokens.io",
    ),
    framework="fastapi",
    recipe_list=[
        emailverification.init("REQUIRED"),
        passwordless.init(
            contact_config=ContactEmailOrPhoneConfig(),
            flow_type="USER_INPUT_CODE_AND_MAGIC_LINK",
        ),
        session.init(),
    ],
)

def verify_email_for_passwordless_users():
    pagination_token = None
    done = False

    while not done:
        res = get_users_newest_first(
            limit=100,
            pagination_token=pagination_token,
            include_recipe_ids=["passwordless"]
        )

        for user in res.users:
            if user.email is not None:
                token_res = create_email_verification_token(user.user_id, user.email)
                if isinstance(token_res, CreateEmailVerificationTokenOkResult):
                    verify_email_using_token(token_res.token)

        done = res.next_pagination_token is None
        if not done:
            pagination_token = res.next_pagination_token

verify_email_for_passwordless_users()
```

#### User roles

The `UserRoles` recipe now adds role and permission information into the access token payload by default. If you are already doing this manually, this will result in duplicate data in the access token.

-   You can disable this behaviour by setting `skip_adding_roles_to_access_token` and `skip_adding_permissions_to_access_token` to true in the recipe init.
-   Check how to use the new claims in the updated guide: https://supertokens.com/docs/userroles/protecting-routes


## [0.10.4] - 2022-08-30
## Features:
- Add support for User ID Mapping using `create_user_id_mapping`, `get_user_id_mapping`, `delete_user_id_mapping`, `update_or_delete_user_id_mapping` functions

## [0.10.3] - 2022-08-29

### Bug fix
- Send FORM_FIELD error with 200 status code instead of 500 on invalid request body or when user passes non-string values as email ID for `/auth/signin`

### Changes
- Add to test to ensure that overrides are applying correctly in methods called on SessionContainer instances

## [0.10.2] - 2022-07-14
### Bug fix
- Make `user_context` optional in userroles recipe syncio functions.

## [0.10.1] - 2022-07-11

### Documentation:
- Added `pdoc` template files to project inside `docs-templates` directory
- Updated `build-docs` in Makefile to use `docs-templates` as the template directory while generating docs using `pdoc`
- Updated `html.mako` template to have a single `h1` tag and have a default meta description tag

### Changes
- Relax version requirements for `httpx`, `cryptography`, and `asgiref` to fix https://github.com/supertokens/supertokens-python/issues/207

## [0.10.0] - 2022-07-04

- Update tests to cover `resend_code` feature in `passwordless` and `thirdpartypasswordless` recipe.
- Update usermetadata tests to ensure that utf8 chars are supported.
- Mark tests as skipped if core version requirements are not met.
- Use [black](https://github.com/psf/black) instead of `autopep8` to format code.
- Add frontend integration tests for `django2x`

### Bug fix:

- Clears cookies when `revoke_session` is called using the session container, even if the session did not exist from before: https://github.com/supertokens/supertokens-node/issues/343

### Breaking changes:
- Change request arg type in session recipe functions from Any to BaseRequest.
- Changes session function recipe interfaces to not throw an `UNAUTHORISED` error when the input is a session_handle: https://github.com/supertokens/backend/issues/83
  - `get_session_information` now returns `None` if the session does not exist.
  - `update_session_data` now returns `False` if the input `session_handle` does not exist.
  - `update_access_token_payload` now returns `False` if the input `session_handle` does not exist.
  - `regenerate_access_token` now returns `None` if the input access token's `session_handle` does not exist.
  - The `session_class` functions have not changed in behaviour and still throw `UNAUTHORISED` error. This works cause the `session_class` works on the current session and not some other session.


### Features:
- Adds default `user_context` for API calls that contains the request object. It can be used in APIs / functions override like this:

```python
def apis_override_email_password(param: APIInterface):
    og_sign_in_post = param.sign_in_post

    async def sign_in_post(
        form_fields: List[FormField],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ):
        req = user_context.get("_default", {}).get("request")
        if req:
            # do something with the request

        return await og_sign_in_post(form_fields, api_options, user_context)

    param.sign_in_post = sign_in_post
    return param

def functions_override_email_password(param: RecipeInterface):
    og_sign_in = param.sign_in

    async def sign_in(email: str, password: str, user_context: Dict[str, Any]):
        req = user_context.get("_default", {}).get("request")
        if req:
            # do something with the request

        return await og_sign_in(email, password, user_context)

    param.sign_in = sign_in
    return param

init(
    ...,
    recipe_list=[
        emailpassword.init(
            override=emailpassword.InputOverrideConfig(
                apis=apis_override_email_password,
                functions=functions_override_email_password,
            )
        ),
        session.init(),
    ],
)
```


### Documentation
- Add more details in the `CONTRIBUTING.md` to make it beginner friendly.


## [0.9.1] - 2022-06-27
### Features:

- Introduce `userroles` recipe.
```python
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import userroles
from supertokens_python.recipe.userroles.asyncio import create_new_role_or_add_permissions, add_role_to_user

init(
    supertokens_config=SupertokensConfig('http://localhost:3567'),
    app_info=InputAppInfo(
        app_name='SuperTokens Demo',
        api_domain='https://api.supertokens.io',
        website_domain='supertokens.io'
    ),
    framework='flask',
    recipe_list=[userroles.init()]
)

user_id = "userId"
role = "role"
permissions = ["perm1", "perm2"]

# Functions to use inside your views:
# Create a new role with a few permissions:
result = await create_new_role_or_add_permissions(role, permissions)
# Add role to the user:
result = await add_role_to_user(user_id, role)
# Check documentation for more examples..
```

## [0.9.0] - 2022-06-23
### Fixes
- Fixes Cookie same_site config validation.
- Remove `<Recipe>(Email|SMS)TemplateVars` in favour of `(Email|SMS)TemplateVars` for better DX.

### Breaking change
-   https://github.com/supertokens/supertokens-node/issues/220
    -   Adds `{status: "GENERAL_ERROR", message: string}` as a possible output to all the APIs.
    -   Changes `FIELD_ERROR` output status in third party recipe API to be `GENERAL_ERROR`.
    -   Replaced `FIELD_ERROR` status type in third party signinup API with `GENERAL_ERROR`.
    -   Removed `FIELD_ERROR` status type from third party signinup recipe function.
-   If sms or email sending failed in passwordless recipe APIs, we now throw a regular JS error from the API as opposed to returning a `GENERAL_ERROR` to the client.
-   If there is an error whilst getting the profile info about a user from a third party provider (in /signinup POST API), then we throw a regular JS error instead of returning a `GENERAL_ERROR` to the client.
- Make email and sms delivery ingredient interfaces developer friendly:
    - Remove the need of `SMSDeliveryTwilioConfig`, `EmailDeliverySMTPConfig`, and `SupertokensServiceConfig`.
    - Export `(.*)OverrideInput` and `(Email|SMS)DeliveryOverrideInput` from the relevant recipes.
    - Rename `Type<Recipe>EmailDeliveryInput` to `<Recipe>EmailTemplateVars`
    - Export `EmailTemplateVars` (alias of `<Recipe>EmailTemplateVars`) from all the relevant recipes
    - Export `PasswordlessLogin(Email|SMS)TemplateVars`, `PasswordResetEmailTemplateVars`, and `VerificationEmailTemplateVars` from relevant recipes.
    - Rename `(.*)ServiceConfig` to `(.*)Settings` for readability.
    - Rename arg `input_` to `template_vars` in `EmailDeliveryInterface.send_email` and `SMTPServiceInterface.send_sms` functions.
    - Rename arg `input_` to `content` and `template_vars` in `SMTPServiceInterface.send_raw_email` and `SMTPServiceInterface.get_content` functions respectively.
    - Rename arg `get_content_result` to `content` and `input_` to `template_vars` in `TwilioServiceInterface.send_raw_email` and `TwilioServiceInterface.get_content` functions respectively.
- Removes support for FDI < 1.14

### Changes
-   Changes `get_email_for_user_id` function inside thirdpartypasswordless to take into account passwordless emails and return an empty string in case a passwordless email doesn't exist. This helps situations where the dev wants to customise the email verification functions in the thirdpartypasswordless recipe.

## [0.8.4] - 2022-06-17
### Added

-   `email_delivery` user config for Emailpassword, Thirdparty, ThirdpartyEmailpassword, Passwordless and ThirdpartyPasswordless recipes.
-   `sms_delivery` user config for Passwordless and ThirdpartyPasswordless recipes.
-   `Twilio` service integartion for `sms_delivery` ingredient.
-   `SMTP` service integration for `email_delivery` ingredient.
-   `Supertokens` service integration for `sms_delivery` ingredient.

### Deprecated

-   For Emailpassword recipe input config, `reset_password_using_token_feature.create_and_send_custom_email` and `email_verification_feature.create_and_send_custom_email` have been deprecated.
-   For Thirdparty recipe input config, `email_verification_feature.create_and_send_custom_email` has been deprecated.
-   For ThirdpartyEmailpassword recipe input config, `reset_password_using_token_feature.create_and_send_custom_email` and `email_verification_feature.create_and_send_custom_email` have been deprecated.
-   For Passwordless recipe input config, `create_and_send_custom_email` and `createAndSendCustomTextMessage` have been deprecated.
-   For ThirdpartyPasswordless recipe input config, `create_and_send_custom_email`, `createAndSendCustomTextMessage` and `email_verification_feature.create_and_send_custom_email` have been deprecated.


### Migration

Following is an example of ThirdpartyPasswordless recipe migration. If your existing code looks like

```python
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import thirdpartypasswordless

async def send_pless_login_email(input_: TypePasswordlessEmailDeliveryInput, user_context: Dict[str, Any]):
    print("SEND_PLESS_LOGIN_EMAIL", input_.email, input_.user_input_code)

async def send_pless_login_sms(input_: TypeThirdPartyPasswordlessSmsDeliveryInput, user_context: Dict[str, Any]):
    print("SEND_PLESS_LOGIN_SMS", input_.phone_number, input_.user_input_code)

async def send_ev_verification_email(user: TpPlessUser, link: str, user_context: Any):
    print("SEND_EV_LOGIN_SMS", user.email, user.phone_number, user.third_party_info)


init(
    supertokens_config=SupertokensConfig('http://localhost:3567'),
    app_info=InputAppInfo(
        api_domain="...",
        app_name="...",
        website_domain="...",
    ),
    framework='...',
    recipe_list=[thirdpartypasswordless.init(
        contact_config=passwordless.ContactEmailOrPhoneConfig(
            create_and_send_custom_email=send_pless_login_email,
            create_and_send_custom_text_message=send_pless_login_sms,
        ),
        flow_type='...',
        email_verification_feature=thirdpartypasswordless.InputEmailVerificationConfig(
            create_and_send_custom_email=send_ev_verification_email,
        )
    )]
)
```

After migration to using new `email_delivery` and `sms_delivery` config, your code would look like:

```python
from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryInterface, EmailDeliveryConfig
from supertokens_python.ingredients.smsdelivery.types import SMSDeliveryInterface, SMSDeliveryConfig
from supertokens_python.recipe import thirdpartypasswordless, passwordless

from supertokens_python.recipe.emailverification.types import TypeEmailVerificationEmailDeliveryInput


async def send_pless_login_email(input_: TypePasswordlessEmailDeliveryInput, user_context: Dict[str, Any]):
    print("SEND_PLESS_LOGIN_EMAIL", input_.email, input_.user_input_code)

async def send_pless_login_sms(input_: TypeThirdPartyPasswordlessSmsDeliveryInput, user_context: Dict[str, Any]):
    print("SEND_PLESS_LOGIN_SMS", input_.phone_number, input_.user_input_code)

async def send_ev_verification_email(user: TpPlessUser, link: str, user_context: Any):
    print("SEND_EV_LOGIN_SMS", user.email, user.phone_number, user.third_party_info)


class EmailDeliveryService(EmailDeliveryInterface):
    async def send_email(self, input_: TypeThirdPartyPasswordlessEmailDeliveryInput, user_context: Dict[str, Any]):
        if isinstance(input_, TypeEmailVerificationEmailDeliveryInput):
            await send_ev_verification_email(input_, user_context)
        elif isinstance(input_, TypePasswordlessEmailDeliveryInput):
            await send_pless_login_email(input_, user_context)

class SMSDeliveryService(SMSDeliveryInterface):
    async def send_sms(self, input_: TypeThirdPartyPasswordlessSmsDeliveryInput, user_context: Dict[str, Any]):
        await send_pless_login_sms(input_, user_context)

init(
    supertokens_config=SupertokensConfig('http://localhost:3567'),
    app_info=InputAppInfo(
        app_name="...",
        api_domain="...",
        website_domain="...",
    ),
    framework='...',
    recipe_list=[thirdpartypasswordless.init(
        contact_config=passwordless.ContactEmailOrPhoneConfig(),
        flow_type='...',
        email_delivery=EmailDeliveryConfig(
            service=EmailDeliveryService(),
        ),
        sms_delivery=SMSDeliveryConfig(
            service=SMSDeliveryService(),
        ),
    )]
)
```

## [0.8.3] - 2022-06-09
- Fix bugs in syncio functions across all the recipes
- Fixes bug in resend code POST API in passwordless recipe to use the correct instance type during checks.
- Fixes bug in thirdpartypasswordless recipe to prevent infinite loop during resent code API

## [0.8.2] - 2022-05-27
- Update phonenumbers lib dependency version
- Adds type checks to the parameters of the emailpassword init funtion.
- Adds type checks to the parameters of the emailverification init funtion.
- Adds type checks to the parameters of the jwt init funtion.
- Adds type checks to the parameters of the openid init funtion.
- Adds type checks to the parameters of the session init funtion.
- Adds type checks to the parameters of the passwordless init funtion.
- Adds type checks to the parameters of the thirdparty init funtion.
- Adds type checks to the parameters of the thirdpartyemailpassword init funtion.
- Adds type checks to the parameters of the thirdpartypasswordless init funtion.
- Adds type checks to the parameters of the usermetadata init funtion.
- Adds django with thirdpartyemailpassword example.

## [0.8.1]
- Fixed execute_async to check and use asyncio mode.
- Ignores any exception from send_telemetry, not to prevent the app from starting up.

## [0.8.0]
- Updates `RecipeInterface` and `APIInterface` methods to return exact return types instead of abstract base types, for the emailpassword recipe.
- Updates `RecipeInterface` and `APIInterface` methods to return exact return types instead of abstract base types, for the thirdparty recipe.
- Updates `RecipeInterface` and `APIInterface` methods to return exact return types instead of abstract base types, for the passwordless recipe.
- Updates `RecipeInterface` and `APIInterface` methods to return exact return types instead of abstract base types, for the openid recipe.
- Updates `RecipeInterface` and `APIInterface` methods to return exact return types instead of abstract base types, for the JWT recipe.
- Updates `RecipeInterface` and `APIInterface` methods to return exact return types instead of abstract base types, for the session recipe.
- Updates `RecipeInterface` methods to return exact return types instead of abstract base types, for the usermetadata recipe.
- Adds `EmailPasswordSignInOkResult`, `EmailPasswordSignUpOkResult` and `ThirdPartySignInUpOkResult` to use the thirdpartyemailpassword recipe's `User` class.
- Adds `ThirdPartySignInUpPostOkResult`, `EmailPasswordSignInPostOkResult` and `EmailPasswordSignUpPostOkResult` to use the thirdpartyemailpassword recipe's `User` class.
- Renames wrongly named `ResetPasswordUsingTokenWrongUserIdErrorResult` to `ResetPasswordUsingTokenInvalidTokenError`, one of the return types of `reset_password_using_token` method in the `RecipeInterface`.
- Removes unused classes `GeneratePasswordResetTokenResponse`, `EmailExistsResponse` and `PasswordResetResponse`.
- Removed `third_party_info` from emailpassword `User` class.
- Exports re-used Result and Response classes from `thirdparty` & `emailpassword` recipe interfaces in the `thirdpartyemailpassword` recipe interfaces.
- Exports re-used Result and Response classes from `thirdparty` & `passwordless` recipe interfaces in the `thirdpartypasswordless` recipe interfaces.
- Renames `*ErrorResult` classes to `*Error`.
- Renames `*ErrorResponse` classes to `*Error`.
- Renames `*OkResponse` classes to `*OkResult`.
- Renames `*ResultOk` classes to `*OkResult`.

## [0.7.3] - 2022-05-12
- Fixed execute_async to check and use asyncio mode.
- Ignores any exception from send_telemetry, not to prevent the app from starting up.

## [0.7.2] - 2022-05-08
- Bug fix in telemetry data API

## [0.7.1] - 2022-05-06
- Updates Project Setup, Modifying Code and Testing sections in the contributing guide
- Fixed async execution of `send_telemetry` in init and `call_get_handshake_info` in session recipe implementation.
- Fixed `Content-length` in FastAPI Response wrapper.

## [0.7.0] - 2022-04-28
- Changes third party provider type to get client ID dynamically so that it can be changed based on user context.

## [0.6.7] - 2022-04-23
- Adds delete email (`delete_email_for_user`) and phone number (`delete_phone_number_for_user`) functions for passwordless and thirdpartypasswordless recipe
- Adds check for user type in update passwordless info in thirdpartypasswordless recipe

## [0.6.6] - 2022-04-22
- Fixes issue in user metadata recipe where as are exposing async functions in the syncio file.

## [0.6.5] - 2022-04-18
- Upgrade and freeze pyright version
- Rename `compare_version` to `get_max_version` for readability
- Add user metadata recipe

## [0.6.4] - 2022-04-11
- bug fix in `default_create_and_send_custom_email` for emailverification recipe where we were not sending the email if env var was not set.
- Fix telemetry issues related to asyncio when using FastAPI. Related issue: https://github.com/supertokens/supertokens-core/issues/421
- adds git action for running tests

## [0.6.3] - 2022-04-09
- Setup logging for easier debugging
- Adds github action for checking all things checked by pre commit hook

## [0.6.2] - 2022-04-07
- Fix Passwordless OTP recipe phone number field to fix https://github.com/supertokens/supertokens-core/issues/416

## [0.6.1] - 2022-03-29

- Expands allowed version range for httpx library to fix https://github.com/supertokens/supertokens-python/issues/98

## [0.6.0] - 2022-03-26

### Changes
- Removes dependency on framework specific dependencies (`werkzeug` and `starlette`)

### Breaking change:
- Import for fastapi middleware:
   - Old
      ```
      from supertokens_python.framework.fastapi import Middleware

      app = FastAPI()
      app.add_middleware(Middleware)
      ```
   - New
      ```
      from supertokens_python.framework.fastapi import get_middleware

      app = FastAPI()
      app.add_middleware(get_middleware())
      ```

### Fixes
- `user_context` was passed incorrectly to the `create_new_session_function`.

## [0.5.3] - 2022-03-26
### Fixes
- Bug in user pagination functions: https://github.com/supertokens/supertokens-python/issues/95


## [0.5.2] - 2022-03-17
### Fixes
- https://github.com/supertokens/supertokens-python/issues/90
- Thirdpartypasswordless recipe + tests

### Changed:
- Added new function to BaseRequest class called `set_session_as_none` to set session object to None.

## [0.5.1] - 2022-03-02

### Fixes:
- Bug where a user had to add dependencies on all frameworks when using the SDK: https://github.com/supertokens/supertokens-python/issues/82

## [0.5.0] - 2022-02-03

### Breaking Change
- User context property added for all recipes' apis and functions
- Removes deprecated functions in recipe for user pagination and user count
- Changed email verification input functions' user type in emailpassword to be equal to emailpassword's user and not emailverification user.
- All session recipe's error handler not need to return `BaseResponse`.
- Session's recipe `get_session_information` returns a `SessionInformationResult` class object instead of a `dict` for easier consumption.
- `get_link_domain_and_path` config in passwordless recipe now takes a class type input as opposed to a string input as the first param
- Renamed `Session` to `SessionContainer` in session
- Upgrades `typing_extensions` to version 4.1.1
- Renames functions in ThirdPartyEmailPassword recipe (https://github.com/supertokens/supertokens-node/issues/219):
    -   Recipe Interface:
        -   `sign_in_up` -> `thirdparty_sign_in_up`
        -   `sign_up` -> `emailpassword_sign_up`
        -   `sign_in` -> `emailpassword_sign_in`
    -   API Interface:
        -   `email_exists_get` -> `emailpassword_email_exists_get`
    -   User exposed functions (in `recipe/thirdpartyemailpassword/asyncio` and `recipe/thirdpartyemailpassword/syncio`)
        -   `sign_in_up` -> `thirdparty_sign_in_up`
        -   `sign_up` -> `emailpassword_sign_up`
        -   `sign_in` -> `emailpassword_sign_in`

### Added
- Returns session from all APIs where a session is created
- Added `regenerate_access_token` as a new recipe function for the session recipe.
- Strong typings.

### Change
- Changed async_to_sync_wrapper.py file to make it simpler
- Remove default `= None` for functions internal to the package

### Bug fix:
- If logging in via social login and the email is already verified from the provider's side, it marks the email as verified in SuperTokens core.
- Corrects how override is done in thirdpartyemailpassword recipe and API implementation

## [0.4.1] - 2022-01-27

### Added
-   add workflow to verify if pr title follows conventional commits

### Changed
- Added userId as an optional property to the response of `recipe/user/password/reset` (compatibility with CDI 2.12).
- Adds ability to give a path for each of the hostnames in the connectionURI: https://github.com/supertokens/supertokens-node/issues/252

### Fixed
- Bug fixes in Literal import which caused issues when using the sdk with python version 3.7.
- Fixes https://github.com/supertokens/supertokens-node/issues/244 - throws an error if a user tries to update email / password of a third party login user.

## [0.4.0] - 2022-01-09

### Added
-   Adds passwordless recipe
-   Adds compatibility with FDI 1.12 and CDI 2.11

## [0.3.1] - 2021-12-20

### Fixes
- Bug in ThirdpartyEmailpassword recipe init function when InputSignUpFeature is not passed.

### Added
- delete_user function
- Compatibility with CDI 2.10

## [0.3.0] - 2021-12-10

### Breaking Change
- Config changes

### Added
- Added `mode` config for FastAPI which now supports both `asgi` and `wsgi`.
- The ability to enable JWT creation with session management, this allows easier integration with services that require JWT based authentication: https://github.com/supertokens/supertokens-core/issues/250
- You can do BaseRequest.request to get the original request object. Fixes #61


## [0.2.3] - 2021-12-07
### Fixes

- Removes use of apiGatewayPath from apple's redirect URI since that is already there in the apiBasePath


## [0.2.2] - 2021-11-22

### Added
- Sign in with Discord, Google workspaces.

### Changes
- Allow sending of custom response: https://github.com/supertokens/supertokens-node/issues/197
- Change `set_content` to `set_json_content` in all the frameworks
- Adds `"application/json; charset=utf-8"` header to json responses.

## [0.2.1] - 2021-11-10

### Changes
- When routing, ignores `rid` value `"anti-csrf"`: https://github.com/supertokens/supertokens-python/issues/54
- `get_redirect_uri` function added to social providers in case we set the `redirect_uri` on the backend.
- Adds optional `is_default` param to auth providers so that they can be reused with different credentials.
- Verifies ID Token sent for sign in with apple as per https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/verifying_a_user
- Removes empty awslambda folder from framework
- If json parsing fails in the frameworks, catches those exceptions and returns an empty object.

## [0.2.0] - 2021-10-22

### Breaking change
- Removes `sign_in_up_post` from thirdpartyemailpassword API interface and replaces it with three APIs: `email_password_sign_in_post`, `email_password_sign_up_post` and `third_party_sign_in_up_post`: https://github.com/supertokens/supertokens-node/issues/192
- Renames all "jwt" related functions in session recipe to use "access_token" instead
- jwt recipe and unit tests
- Support for FDI 1.10: Allow thirdparty `/signinup POST` API to take `authCodeResponse` XOR `code` so that it can supprt OAuth via PKCE
- Apple provider disabled for now

### Bug Fixes
- Bug fix: https://github.com/supertokens/supertokens-python/issues/42
- Bug fix: https://github.com/supertokens/supertokens-python/issues/10
- Bug fix: https://github.com/supertokens/supertokens-python/issues/13

## [0.1.0] - 2021-10-18
### Changes
- all the user facing async functions now needs to be imported from asyncio sub directory. For example, importing the async implementation of create_new_session from session recipe has changed from:
    ```python3
    from supertokens_python.recipe.session import create_new_session
    ```
    to:
    ```python3
    from supertokens_python.recipe.session.asyncio import create_new_session
    ```
- sync versions of the functions are now needs to be imported from syncio directory instead of the sync directory
- all the license comments now uses single line comment structure instead of multi-line comment structure

### Added
- auth-react tests for flask and django
- if running django in async way, set `mode` to `asgi` in `config`

## [0.0.3] - 2021-10-13
### Added
- Adds OAuth development keys for Google and Github for faster recipe implementation.
- Removed the Literal from python 3.8 and added Literal from typing_extensions package. Now supertokens_python can be used with python 3.7 .


## [0.0.2] - 2021-10-09
### Fixes
- dependency issues for frameworks

## [0.0.1] - 2021-09-10
### Added
- Multiple framework support. Currently supporting Django, Flask(1.x) and Fastapi.
- BaseRequest and BaseResponse interfaces which are used inside recipe instead of previously used Response and Request from Fastapi.
- Middleware, error handlers and verify session for each framework.
- Created a wrapper for async to sync for supporting older version of python web frameworks.
- Base tests for each framework.
- New requirements in the setup file.
