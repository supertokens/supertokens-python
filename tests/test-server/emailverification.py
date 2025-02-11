from flask import Flask, jsonify, request
from supertokens_python import async_to_sync_wrapper
from supertokens_python.framework.flask.flask_request import FlaskRequest
from supertokens_python.recipe.emailverification.interfaces import (
    CreateEmailVerificationTokenOkResult,
    VerifyEmailUsingTokenOkResult,
)
from supertokens_python.recipe.emailverification.syncio import (
    create_email_verification_token,
)


def add_emailverification_routes(app: Flask):
    @app.route("/test/emailverification/isemailverified", methods=["POST"])  # type: ignore
    def is_email_verified_api():  # type: ignore
        from supertokens_python import convert_to_recipe_user_id
        from supertokens_python.recipe.emailverification.syncio import is_email_verified

        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        recipe_user_id = convert_to_recipe_user_id(data["recipeUserId"])
        email = data.get("email")
        user_context = data.get("userContext", {})

        response = is_email_verified(recipe_user_id, email, user_context)
        return jsonify(response)

    @app.route("/test/emailverification/createemailverificationtoken", methods=["POST"])  # type: ignore
    def f():  # type: ignore
        from supertokens_python import convert_to_recipe_user_id

        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        recipe_user_id = convert_to_recipe_user_id(data["recipeUserId"])
        tenant_id = data.get("tenantId", "public")
        email = None if "email" not in data else data["email"]
        user_context = data.get("userContext")

        response = create_email_verification_token(
            tenant_id, recipe_user_id, email, user_context
        )

        if isinstance(response, CreateEmailVerificationTokenOkResult):
            return jsonify({"status": "OK", "token": response.token})
        else:
            return jsonify({"status": "EMAIL_ALREADY_VERIFIED_ERROR"})

    @app.route("/test/emailverification/verifyemailusingtoken", methods=["POST"])  # type: ignore
    def f2():  # type: ignore
        from supertokens_python.recipe.emailverification.syncio import (
            verify_email_using_token,
        )

        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        token = data["token"]
        attempt_account_linking = data.get("attemptAccountLinking", True)
        user_context = data.get("userContext", {})

        response = verify_email_using_token(
            tenant_id, token, attempt_account_linking, user_context
        )

        if isinstance(response, VerifyEmailUsingTokenOkResult):
            return jsonify(
                {
                    "status": "OK",
                    "user": {
                        "email": response.user.email,
                        "recipeUserId": {
                            # this is intentionally done this way cause the test in the test suite expects this way.
                            "recipeUserId": response.user.recipe_user_id.get_as_string()
                        },
                    },
                }
            )
        else:
            return jsonify({"status": "EMAIL_VERIFICATION_INVALID_TOKEN_ERROR"})

    @app.route("/test/emailverification/unverifyemail", methods=["POST"])  # type: ignore
    def unverify_email():  # type: ignore
        from supertokens_python.recipe.emailverification.syncio import unverify_email
        from supertokens_python.types import RecipeUserId

        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        recipe_user_id = RecipeUserId(data["recipeUserId"])
        email = data.get("email")
        user_context = data.get("userContext", {})

        unverify_email(recipe_user_id, email, user_context)
        return jsonify({"status": "OK"})

    @app.route(
        "/test/emailverification/updatesessionifrequiredpostemailverification",
        methods=["POST"],
    )  # type: ignore
    def update_session_if_required_post_email_verification():  # type: ignore
        from session import convert_session_to_container, convert_session_to_json
        from supertokens_python.recipe.emailverification import EmailVerificationRecipe
        from supertokens_python.types import RecipeUserId

        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        recipe_user_id_whose_email_got_verified = RecipeUserId(
            data["recipeUserIdWhoseEmailGotVerified"]["recipeUserId"]
        )
        session = convert_session_to_container(data) if "session" in data else None

        session_resp = async_to_sync_wrapper.sync(
            EmailVerificationRecipe.get_instance_or_throw().update_session_if_required_post_email_verification(
                recipe_user_id_whose_email_got_verified=recipe_user_id_whose_email_got_verified,
                session=session,
                req=FlaskRequest(request),
                user_context=data.get("userContext", {}),
            )
        )
        return jsonify(
            None if session_resp is None else convert_session_to_json(session_resp)
        )
