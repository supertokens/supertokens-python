import supertokens_python.recipe.emailpassword.syncio as emailpassword
from flask import Flask, jsonify, request
from session import convert_session_to_container  # pylint: disable=import-error
from supertokens_python.recipe.emailpassword.interfaces import (
    EmailAlreadyExistsError,
    SignInOkResult,
    SignUpOkResult,
    UnknownUserIdError,
    UpdateEmailOrPasswordEmailChangeNotAllowedError,
    UpdateEmailOrPasswordOkResult,
    WrongCredentialsError,
)
from supertokens_python.types import RecipeUserId

from utils import (  # pylint: disable=import-error
    serialize_recipe_user_id,
    serialize_user,
)  # pylint: disable=import-error


def add_emailpassword_routes(app: Flask):
    @app.route("/test/emailpassword/signup", methods=["POST"])  # type: ignore
    def emailpassword_signup():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})
        tenant_id = data.get("tenantId", "public")
        email = data["email"]
        password = data["password"]
        user_context = data.get("userContext")
        session = convert_session_to_container(data) if "session" in data else None

        response = emailpassword.sign_up(
            tenant_id, email, password, session, user_context
        )

        if isinstance(response, SignUpOkResult):
            return jsonify(
                {
                    "status": "OK",
                    **serialize_user(
                        response.user, request.headers.get("fdi-version", "")
                    ),
                    **serialize_recipe_user_id(
                        response.recipe_user_id, request.headers.get("fdi-version", "")
                    ),
                }
            )
        elif isinstance(response, EmailAlreadyExistsError):
            return jsonify({"status": "EMAIL_ALREADY_EXISTS_ERROR"})
        else:
            return jsonify(
                {
                    "status": response.status,
                    "reason": response.reason,
                }
            )

    @app.route("/test/emailpassword/signin", methods=["POST"])  # type: ignore
    def emailpassword_signin():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        email = data["email"]
        password = data["password"]
        user_context = data.get("userContext")
        session = convert_session_to_container(data) if "session" in data else None

        response = emailpassword.sign_in(
            tenant_id, email, password, session, user_context
        )

        if isinstance(response, SignInOkResult):
            return jsonify(
                {
                    "status": "OK",
                    **serialize_user(
                        response.user, request.headers.get("fdi-version", "")
                    ),
                    **serialize_recipe_user_id(
                        response.recipe_user_id, request.headers.get("fdi-version", "")
                    ),
                }
            )
        elif isinstance(response, WrongCredentialsError):
            return jsonify({"status": "WRONG_CREDENTIALS_ERROR"})
        else:
            return jsonify(
                {
                    "status": response.status,
                    "reason": response.reason,
                }
            )

    @app.route("/test/emailpassword/createresetpasswordlink", methods=["POST"])  # type: ignore
    def emailpassword_create_reset_password_link():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        user_id = data["userId"]
        user_context = data.get("userContext")

        response = emailpassword.create_reset_password_link(
            tenant_id, user_id, user_context
        )

        if isinstance(response, str):
            return jsonify({"status": "OK", "link": response})
        else:
            return jsonify({"status": "UNKNOWN_USER_ID_ERROR"})

    @app.route("/test/emailpassword/updateemailorpassword", methods=["POST"])  # type: ignore
    def emailpassword_update_email_or_password():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        recipe_user_id = RecipeUserId(data["recipeUserId"])
        email = data.get("email")
        password = data.get("password")
        apply_password_policy = data.get("applyPasswordPolicy")
        tenant_id_for_password_policy = data.get("tenantIdForPasswordPolicy")
        user_context = data.get("userContext")

        response = emailpassword.update_email_or_password(
            recipe_user_id,
            email,
            password,
            apply_password_policy,
            tenant_id_for_password_policy,
            user_context,
        )

        if isinstance(response, UpdateEmailOrPasswordOkResult):
            return jsonify({"status": "OK"})
        elif isinstance(response, UnknownUserIdError):
            return jsonify({"status": "UNKNOWN_USER_ID_ERROR"})
        elif isinstance(response, EmailAlreadyExistsError):
            return jsonify({"status": "EMAIL_ALREADY_EXISTS_ERROR"})
        elif isinstance(response, UpdateEmailOrPasswordEmailChangeNotAllowedError):
            return jsonify(
                {"status": "EMAIL_CHANGE_NOT_ALLOWED_ERROR", "reason": response.reason}
            )
        else:
            return jsonify(
                {
                    "status": "PASSWORD_POLICY_VIOLATED_ERROR",
                    "failureReason": response.failure_reason,
                }
            )
