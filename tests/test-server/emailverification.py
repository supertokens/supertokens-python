from flask import Flask, request, jsonify

from supertokens_python.recipe.emailverification.interfaces import (
    CreateEmailVerificationTokenOkResult,
    VerifyEmailUsingTokenOkResult,
)
from supertokens_python.recipe.emailverification.syncio import (
    create_email_verification_token,
)


def add_emailverification_routes(app: Flask):
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
        attempt_account_linking = data.get("attemptAccountLinking", False)
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
                            "recipeUserId": response.user.recipe_user_id.get_as_string()
                        },
                    },
                }
            )
        else:
            return jsonify({"status": "EMAIL_VERIFICATION_INVALID_TOKEN_ERROR"})
