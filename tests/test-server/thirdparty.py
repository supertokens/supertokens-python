from flask import Flask, request, jsonify

from session import convert_session_to_container  # pylint: disable=import-error
from supertokens_python.recipe.thirdparty.interfaces import (
    EmailChangeNotAllowedError,
    ManuallyCreateOrUpdateUserOkResult,
    SignInUpNotAllowed,
)
from supertokens_python.recipe.thirdparty.syncio import manually_create_or_update_user
from utils import (  # pylint: disable=import-error
    serialize_user,
    serialize_recipe_user_id,
)  # pylint: disable=import-error


def add_thirdparty_routes(app: Flask):
    @app.route("/test/thirdparty/manuallycreateorupdateuser", methods=["POST"])  # type: ignore
    def thirdpartymanuallycreateorupdate():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        third_party_id = data["thirdPartyId"]
        third_party_user_id = data["thirdPartyUserId"]
        email = data["email"]
        is_verified = data["isVerified"]
        user_context = data.get("userContext", {})

        session = None
        if data.get("session"):
            session = convert_session_to_container(data["session"])

        response = manually_create_or_update_user(
            tenant_id,
            third_party_id,
            third_party_user_id,
            email,
            is_verified,
            session,
            user_context,
        )

        if isinstance(response, ManuallyCreateOrUpdateUserOkResult):
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
        elif isinstance(response, EmailChangeNotAllowedError):
            return jsonify(
                {"status": "EMAIL_CHANGE_NOT_ALLOWED_ERROR", "reason": response.reason}
            )
        elif isinstance(response, SignInUpNotAllowed):
            return jsonify(response.to_json())
        elif isinstance(response, SignInUpNotAllowed):
            return jsonify(response.to_json())
        else:
            return jsonify(
                {
                    "status": response.status,
                    "reason": response.reason,
                }
            )
