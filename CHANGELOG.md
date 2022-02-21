# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

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
