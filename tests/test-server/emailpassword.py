from flask import Flask, request, jsonify
from supertokens_python.recipe.emailpassword.interfaces import (
    CreateResetPasswordLinkOkResult,
    SignInOkResult,
    SignUpOkResult,
    UpdateEmailOrPasswordEmailAlreadyExistsError,
    UpdateEmailOrPasswordOkResult,
    UpdateEmailOrPasswordUnknownUserIdError,
)
import supertokens_python.recipe.emailpassword.syncio as emailpassword


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

        response = emailpassword.sign_up(tenant_id, email, password, user_context)

        if isinstance(response, SignUpOkResult):
            return jsonify(
                {
                    "status": "OK",
                    "user": {
                        "id": response.user.user_id,
                        "email": response.user.email,
                        "timeJoined": response.user.time_joined,
                        "tenantIds": response.user.tenant_ids,
                    },
                }
            )
        else:
            return jsonify({"status": "EMAIL_ALREADY_EXISTS_ERROR"})

    @app.route("/test/emailpassword/signin", methods=["POST"])  # type: ignore
    def emailpassword_signin():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        email = data["email"]
        password = data["password"]
        user_context = data.get("userContext")

        response = emailpassword.sign_in(tenant_id, email, password, user_context)

        if isinstance(response, SignInOkResult):
            return jsonify(
                {
                    "status": "OK",
                    "user": {
                        "id": response.user.user_id,
                        "email": response.user.email,
                        "timeJoined": response.user.time_joined,
                        "tenantIds": response.user.tenant_ids,
                    },
                }
            )
        else:
            return jsonify({"status": "WRONG_CREDENTIALS_ERROR"})

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

        if isinstance(response, CreateResetPasswordLinkOkResult):
            return jsonify({"status": "OK", "link": response.link})
        else:
            return jsonify({"status": "UNKNOWN_USER_ID_ERROR"})

    @app.route("/test/emailpassword/updateemailorpassword", methods=["POST"])  # type: ignore
    def emailpassword_update_email_or_password():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        user_id = data["userId"]
        email = data.get("email")
        password = data.get("password")
        apply_password_policy = data.get("applyPasswordPolicy")
        tenant_id_for_password_policy = data.get("tenantIdForPasswordPolicy")
        user_context = data.get("userContext")

        response = emailpassword.update_email_or_password(
            user_id,
            email,
            password,
            apply_password_policy,
            tenant_id_for_password_policy,
            user_context,
        )

        if isinstance(response, UpdateEmailOrPasswordOkResult):
            return jsonify({"status": "OK"})
        elif isinstance(response, UpdateEmailOrPasswordUnknownUserIdError):
            return jsonify({"status": "UNKNOWN_USER_ID_ERROR"})
        elif isinstance(response, UpdateEmailOrPasswordEmailAlreadyExistsError):
            return jsonify({"status": "EMAIL_ALREADY_EXISTS_ERROR"})
        else:
            return jsonify(
                {
                    "status": "PASSWORD_POLICY_VIOLATED_ERROR",
                    "failureReason": response.failure_reason,
                }
            )
