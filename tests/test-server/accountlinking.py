from flask import Flask, jsonify, request
from session import convert_session_to_container
from supertokens_python import async_to_sync_wrapper, convert_to_recipe_user_id
from supertokens_python.recipe.accountlinking.interfaces import (
    CanCreatePrimaryUserOkResult,
    CanCreatePrimaryUserRecipeUserIdAlreadyLinkedError,
    CreatePrimaryUserOkResult,
    CreatePrimaryUserRecipeUserIdAlreadyLinkedError,
    LinkAccountsAccountInfoAlreadyAssociatedError,
    LinkAccountsOkResult,
    LinkAccountsRecipeUserIdAlreadyLinkedError,
)
from supertokens_python.recipe.accountlinking.recipe import AccountLinkingRecipe
from supertokens_python.recipe.accountlinking.syncio import (
    can_create_primary_user,
    create_primary_user,
    create_primary_user_id_or_link_accounts,
    get_primary_user_that_can_be_linked_to_recipe_user_id,
    is_email_change_allowed,
    is_sign_in_allowed,
    is_sign_up_allowed,
    link_accounts,
    unlink_account,
)
from supertokens_python.recipe.accountlinking.types import AccountInfoWithRecipeId
from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo
from supertokens_python.types import User

from utils import serialize_user  # pylint: disable=import-error


def add_accountlinking_routes(app: Flask):
    @app.route("/test/accountlinking/createprimaryuser", methods=["POST"])  # type: ignore
    def create_primary_user_api():  # type: ignore
        assert request.json is not None
        recipe_user_id = convert_to_recipe_user_id(request.json["recipeUserId"])
        response = create_primary_user(recipe_user_id, request.json.get("userContext"))
        if isinstance(response, CreatePrimaryUserOkResult):
            return jsonify(
                {
                    "status": "OK",
                    **serialize_user(
                        response.user, request.headers.get("fdi-version", "")
                    ),
                    "wasAlreadyAPrimaryUser": response.was_already_a_primary_user,
                }
            )
        elif isinstance(response, CreatePrimaryUserRecipeUserIdAlreadyLinkedError):
            return jsonify(
                {
                    "description": response.description,
                    "primaryUserId": response.primary_user_id,
                    "status": response.status,
                }
            )
        elif isinstance(response, CreatePrimaryUserRecipeUserIdAlreadyLinkedError):
            return jsonify(
                {
                    "description": response.description,
                    "primaryUserId": response.primary_user_id,
                    "status": response.status,
                }
            )
        else:
            return jsonify(
                {
                    "description": response.description,
                    "primaryUserId": response.primary_user_id,
                    "status": response.status,
                }
            )

    @app.route("/test/accountlinking/linkaccounts", methods=["POST"])  # type: ignore
    def link_accounts_api():  # type: ignore
        assert request.json is not None
        recipe_user_id = convert_to_recipe_user_id(request.json["recipeUserId"])
        response = link_accounts(
            recipe_user_id,
            request.json["primaryUserId"],
            request.json.get("userContext"),
        )
        if isinstance(response, LinkAccountsOkResult):
            return jsonify(
                {
                    "status": "OK",
                    **serialize_user(
                        response.user, request.headers.get("fdi-version", "")
                    ),
                    "accountsAlreadyLinked": response.accounts_already_linked,
                }
            )
        elif isinstance(response, LinkAccountsRecipeUserIdAlreadyLinkedError):
            return jsonify(
                {
                    "description": response.description,
                    "primaryUserId": response.primary_user_id,
                    "status": response.status,
                    **serialize_user(
                        response.user, request.headers.get("fdi-version", "")
                    ),
                }
            )
        elif isinstance(response, LinkAccountsAccountInfoAlreadyAssociatedError):
            return jsonify(
                {
                    "description": response.description,
                    "primaryUserId": response.primary_user_id,
                    "status": response.status,
                }
            )
        else:
            return jsonify(
                {
                    "status": response.status,
                }
            )

    @app.route("/test/accountlinking/isemailchangeallowed", methods=["POST"])  # type: ignore
    def is_email_change_allowed_api():  # type: ignore
        assert request.json is not None
        recipe_user_id = convert_to_recipe_user_id(request.json["recipeUserId"])
        session = None
        if "session" in request.json:
            session = convert_session_to_container(request)
        response = is_email_change_allowed(
            recipe_user_id,
            request.json["newEmail"],
            request.json["isVerified"],
            session,
            request.json.get("userContext"),
        )
        return jsonify(response)

    @app.route("/test/accountlinking/unlinkaccount", methods=["POST"])  # type: ignore
    def unlink_account_api():  # type: ignore
        assert request.json is not None
        recipe_user_id = convert_to_recipe_user_id(request.json["recipeUserId"])
        response = unlink_account(
            recipe_user_id,
            request.json.get("userContext"),
        )
        return jsonify(
            {
                "status": response.status,
                "wasRecipeUserDeleted": response.was_recipe_user_deleted,
                "wasLinked": response.was_linked,
            }
        )

    @app.route(
        "/test/accountlinking/createprimaryuseridorlinkaccounts", methods=["POST"]
    )  # type: ignore
    def create_primary_user_id_or_link_accounts_api():  # type: ignore
        assert request.json is not None
        recipe_user_id = convert_to_recipe_user_id(request.json["recipeUserId"])
        session = None
        if "session" in request.json:
            session = convert_session_to_container(request)
        response = create_primary_user_id_or_link_accounts(
            request.json["tenantId"],
            recipe_user_id,
            session,
            request.json.get("userContext", None),
        )
        return jsonify(response.to_json())

    @app.route(
        "/test/accountlinking/getprimaryuserthatcanbelinkedtorecipeuserid",
        methods=["POST"],
    )  # type: ignore
    def get_primary_user_that_can_be_linked_to_recipe_user_id_api():  # type: ignore
        assert request.json is not None
        recipe_user_id = convert_to_recipe_user_id(request.json["recipeUserId"])
        response = get_primary_user_that_can_be_linked_to_recipe_user_id(
            request.json["tenantId"],
            recipe_user_id,
            request.json.get("userContext", None),
        )
        return jsonify(response.to_json() if response else None)

    @app.route("/test/accountlinking/issignupallowed", methods=["POST"])  # type: ignore
    def is_signup_allowed_api():  # type: ignore
        assert request.json is not None
        session = None
        if "session" in request.json:
            session = convert_session_to_container(request)
        response = is_sign_up_allowed(
            request.json["tenantId"],
            AccountInfoWithRecipeId(
                recipe_id=request.json["newUser"]["recipeId"],
                email=(
                    request.json["newUser"]["email"]
                    if "email" in request.json["newUser"]
                    else None
                ),
                phone_number=(
                    request.json["newUser"]["phoneNumber"]
                    if "phoneNumber" in request.json["newUser"]
                    else None
                ),
                third_party=(
                    ThirdPartyInfo(
                        third_party_user_id=request.json["newUser"]["thirdParty"]["id"],
                        third_party_id=request.json["newUser"]["thirdParty"][
                            "thirdPartyId"
                        ],
                    )
                    if "thirdParty" in request.json["newUser"]
                    else None
                ),
            ),
            request.json["isVerified"],
            session,
            request.json.get("userContext", None),
        )
        return jsonify(response)

    @app.route("/test/accountlinking/issigninallowed", methods=["POST"])  # type: ignore
    def is_signin_allowed_api():  # type: ignore
        assert request.json is not None
        recipe_user_id = convert_to_recipe_user_id(request.json["recipeUserId"])
        session = None
        if "session" in request.json:
            session = convert_session_to_container(request)
        response = is_sign_in_allowed(
            request.json["tenantId"],
            recipe_user_id,
            session,
            request.json.get("userContext", None),
        )
        return jsonify(response)

    @app.route(
        "/test/accountlinking/verifyemailforrecipeuseriflinkedaccountsareverified",
        methods=["POST"],
    )  # type: ignore
    def verify_email_for_recipe_user_if_linked_accounts_are_verified_api():  # type: ignore
        assert request.json is not None
        recipe_user_id = convert_to_recipe_user_id(request.json["recipeUserId"])
        user = User.from_json(request.json["user"])
        async_to_sync_wrapper.sync(
            AccountLinkingRecipe.get_instance().verify_email_for_recipe_user_if_linked_accounts_are_verified(
                user=user,
                recipe_user_id=recipe_user_id,
                user_context=request.json.get("userContext"),
            )
        )
        return jsonify({})

    @app.route("/test/accountlinking/cancreateprimaryuser", methods=["POST"])  # type: ignore
    def can_create_primary_user_api():  # type: ignore
        assert request.json is not None
        recipe_user_id = convert_to_recipe_user_id(request.json["recipeUserId"])
        response = can_create_primary_user(
            recipe_user_id, request.json.get("userContext")
        )
        if isinstance(response, CanCreatePrimaryUserOkResult):
            return jsonify(
                {
                    "status": response.status,
                    "wasAlreadyAPrimaryUser": response.was_already_a_primary_user,
                }
            )
        elif isinstance(response, CanCreatePrimaryUserRecipeUserIdAlreadyLinkedError):
            return jsonify(
                {
                    "description": response.description,
                    "primaryUserId": response.primary_user_id,
                    "status": response.status,
                }
            )
        else:
            return jsonify(
                {
                    "description": response.description,
                    "status": response.status,
                    "primaryUserId": response.primary_user_id,
                }
            )
